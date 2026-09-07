//! Apple Account login, two-factor verification, and MME token refresh.

use std::{collections::BTreeMap, io::Cursor};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use plist::{Dictionary, Value};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    Error, Result,
    anisette::identity_headers,
    auth::{PasswordScheme, SrpClient, decrypt_spd, verify_server_proof},
    cloudkit::{AnisetteProvider, DeviceState, HttpRequest, HttpTransport, MmeState, SessionState},
};

const GSA_URL: &str = "https://gsa.apple.com/grandslam/GsService2";
const LOGIN_DELEGATES_URL: &str = "https://setup.icloud.com/setup/iosbuddy/loginDelegates";
const ACCOUNT_SETTINGS_URL: &str = "https://setup.icloud.com/setup/get_account_settings";
const GSA_USER_AGENT: &str = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0";
const GSA_CLIENT_INFO: &str = "<MacBookPro13,2> <Mac OS X;10.15.2;19C57> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>";
const ICLOUD_USER_AGENT: &str = "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0";
const ICLOUD_CLIENT_INFO: &str =
    "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecondFactor {
    TrustedDevice,
    Sms,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct GrandSlamCredentials {
    pub adsid: String,
    pub idms_token: String,
    pub pet: String,
}

impl std::fmt::Debug for GrandSlamCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GrandSlamCredentials(<redacted>)")
    }
}

#[derive(Debug)]
pub struct AuthenticationOutcome {
    pub credentials: GrandSlamCredentials,
    pub second_factor: Option<SecondFactor>,
}

pub struct AccountClient<T, A> {
    transport: T,
    anisette: A,
    device: DeviceState,
}

impl<T: HttpTransport, A: AnisetteProvider> AccountClient<T, A> {
    pub fn new(transport: T, anisette: A, device: DeviceState) -> Self {
        Self {
            transport,
            anisette,
            device,
        }
    }

    pub async fn authenticate(
        &self,
        username: &str,
        password: impl AsRef<[u8]>,
    ) -> Result<AuthenticationOutcome> {
        let srp = SrpClient::new(username, password);
        let init = self
            .gsa_request(dictionary([
                ("A2k", Value::Data(srp.public_a().to_vec())),
                (
                    "ps",
                    Value::Array(vec![
                        Value::String("s2k".into()),
                        Value::String("s2k_fo".into()),
                    ]),
                ),
                ("u", Value::String(username.into())),
                ("o", Value::String("init".into())),
            ]))
            .await?;
        check_status(&init, "GrandSlam initialization")?;
        let scheme = match string(&init, "sp")? {
            "s2k" => PasswordScheme::S2k,
            "s2k_fo" => PasswordScheme::S2kFo,
            other => {
                return Err(Error::Authentication(format!(
                    "unsupported GrandSlam password scheme {other}"
                )));
            }
        };
        let iterations = integer(&init, "i")?;
        let iterations = u32::try_from(iterations)
            .map_err(|_| Error::Authentication("invalid GrandSlam iteration count".into()))?;
        let proof = srp.complete(scheme, data(&init, "s")?, iterations, data(&init, "B")?)?;
        let complete = self
            .gsa_request(dictionary([
                ("c", required(&init, "c")?.clone()),
                ("M1", Value::Data(proof.m1.to_vec())),
                ("u", Value::String(username.into())),
                ("o", Value::String("complete".into())),
            ]))
            .await?;
        check_status(&complete, "GrandSlam completion")?;
        verify_server_proof(&proof, data(&complete, "M2")?)?;
        let decrypted = decrypt_spd(&proof, data(&complete, "spd")?)?;
        let spd = parse_plist(&decrypted)?;
        let second_factor = match nested_string(&complete, &["Status", "au"]) {
            Some("trustedDeviceSecondaryAuth") => Some(SecondFactor::TrustedDevice),
            Some("secondaryAuth") => Some(SecondFactor::Sms),
            Some(other) => {
                return Err(Error::Authentication(format!(
                    "unsupported second-factor method {other}"
                )));
            }
            None => None,
        };
        let pet = nested_string(&spd, &["t", "com.apple.gs.idms.pet", "token"]);
        if second_factor.is_none() && pet.is_none() {
            return Err(Error::Authentication("GrandSlam omitted PET".into()));
        }
        Ok(AuthenticationOutcome {
            credentials: GrandSlamCredentials {
                adsid: string_any(&spd, &["adsid", "DsPrsId"]).ok_or_else(|| {
                    Error::Authentication("GrandSlam omitted account DSID".into())
                })?,
                idms_token: string_any(&spd, &["GsIdmsToken", "GsIdMS"]).unwrap_or_default(),
                // Apple omits the PET from the pre-2FA SPD. The ADSID and IDMS
                // token are sufficient to submit the challenge; a second SRP
                // exchange after verification returns the PET.
                pet: pet.unwrap_or_default().to_owned(),
            },
            second_factor,
        })
    }

    pub async fn trigger_second_factor(
        &self,
        factor: SecondFactor,
        credentials: &GrandSlamCredentials,
    ) -> Result<()> {
        self.second_factor_request(factor, None, credentials).await
    }

    pub async fn submit_second_factor(
        &self,
        factor: SecondFactor,
        code: &str,
        credentials: &GrandSlamCredentials,
    ) -> Result<()> {
        self.second_factor_request(factor, Some(code), credentials)
            .await
    }

    pub async fn login_mobileme(
        &self,
        username: &str,
        credentials: &GrandSlamCredentials,
    ) -> Result<SessionState> {
        let body = plist_bytes(Value::Dictionary(dictionary([
            ("apple-id", Value::String(username.into())),
            (
                "delegates",
                Value::Dictionary(dictionary([(
                    "com.apple.mobileme",
                    Value::Dictionary(Dictionary::new()),
                )])),
            ),
            ("password", Value::String(credentials.pet.clone())),
            (
                "client-id",
                Value::String(self.device.local_user_uuid.clone()),
            ),
        ])))?;
        let mut headers = self.icloud_headers().await?;
        headers.extend([
            ("Authorization".into(), basic(username, &credentials.pet)),
            ("X-Apple-ADSID".into(), credentials.adsid.clone()),
        ]);
        let response = self
            .send("POST", LOGIN_DELEGATES_URL, headers, body)
            .await?;
        let root = parse_plist(&response)?;
        let mobileme = nested(&root, &["delegates", "com.apple.mobileme"]).ok_or_else(|| {
            Error::Authentication("loginDelegates omitted MobileMe result".into())
        })?;
        let status = value_integer(required_dict(mobileme)?, "status")
            .or_else(|| {
                required_dict(&root)
                    .ok()
                    .and_then(|root| value_integer(root, "status"))
            })
            .unwrap_or(-1);
        if status != 0 {
            let message = nested_string(mobileme, &["status-message"])
                .or_else(|| nested_string(&root, &["status-message"]))
                .unwrap_or("unknown error");
            return Err(Error::Authentication(format!(
                "loginDelegates status {status}: {message}"
            )));
        }
        let service_data = nested(mobileme, &["service-data"])
            .ok_or_else(|| Error::Authentication("loginDelegates omitted service data".into()))?;
        let tokens = string_map(
            nested(service_data, &["tokens"])
                .ok_or_else(|| Error::Authentication("loginDelegates omitted tokens".into()))?,
        );
        let mme_auth_token = tokens
            .get("mmeAuthToken")
            .cloned()
            .ok_or_else(|| Error::Authentication("loginDelegates omitted MME token".into()))?;
        let dsid = nested_string(&root, &["dsid"])
            .map(str::to_owned)
            .or_else(|| {
                nested_string(service_data, &["appleAccountInfo", "dsid"]).map(str::to_owned)
            })
            .unwrap_or_else(|| credentials.adsid.clone());
        Ok(SessionState {
            username: username.into(),
            dsid: dsid.clone(),
            mme: MmeState {
                dsid,
                mme_auth_token,
                tokens,
                extra: BTreeMap::new(),
            },
            safari_cloudkit_users: BTreeMap::new(),
            extra: BTreeMap::new(),
        })
    }

    pub async fn refresh_session(&self, session: &mut SessionState) -> Result<()> {
        let mut headers = self.icloud_headers().await?;
        headers.push((
            "Authorization".into(),
            basic(&session.mme.dsid, &session.mme.mme_auth_token),
        ));
        let body = self
            .send("POST", ACCOUNT_SETTINGS_URL, headers, Vec::new())
            .await?;
        let settings = parse_plist(&body)?;
        if let Some(status) = required_dict(&settings)
            .ok()
            .and_then(|d| value_integer(d, "status"))
            && status != 0
        {
            let message = nested_string(&settings, &["status-message"]).unwrap_or("unknown error");
            return Err(Error::Authentication(format!(
                "account refresh status {status}: {message}; run `cargo run -- login` again"
            )));
        }
        let refreshed = nested(&settings, &["tokens"])
            .or_else(|| nested(&settings, &["service-data", "tokens"]))
            .map(string_map)
            .unwrap_or_default();
        if let Some(token) = refreshed.get("mmeAuthToken") {
            session.mme.mme_auth_token.clone_from(token);
        }
        session.mme.tokens.extend(refreshed);
        session
            .mme
            .extra
            .insert("accountSettings".into(), serde_json::to_value(&settings)?);
        Ok(())
    }

    async fn gsa_request(&self, parameters: Dictionary) -> Result<Value> {
        let mut request = dictionary([("cpd", Value::Dictionary(self.cpd().await?))]);
        request.extend(parameters);
        let body = plist_bytes(Value::Dictionary(dictionary([
            (
                "Header",
                Value::Dictionary(dictionary([("Version", Value::String("1.0.1".into()))])),
            ),
            ("Request", Value::Dictionary(request)),
        ])))?;
        let response = self
            .send(
                "POST",
                GSA_URL,
                vec![
                    ("Content-Type".into(), "text/x-xml-plist".into()),
                    ("Accept".into(), "*/*".into()),
                    ("User-Agent".into(), GSA_USER_AGENT.into()),
                    ("X-MMe-Client-Info".into(), GSA_CLIENT_INFO.into()),
                ],
                body,
            )
            .await?;
        let root = parse_plist(&response)?;
        nested(&root, &["Response"])
            .cloned()
            .ok_or_else(|| Error::Authentication("GrandSlam omitted response".into()))
    }

    async fn cpd(&self) -> Result<Dictionary> {
        let mut cpd = dictionary([
            ("bootstrap", Value::Boolean(true)),
            ("icscrec", Value::Boolean(true)),
            ("pbe", Value::Boolean(false)),
            ("prkgen", Value::Boolean(true)),
            ("svct", Value::String("iCloud".into())),
        ]);
        for (name, value) in identity_headers(&self.anisette, &self.device).await? {
            cpd.insert(name, Value::String(value));
        }
        Ok(cpd)
    }

    async fn second_factor_request(
        &self,
        factor: SecondFactor,
        code: Option<&str>,
        credentials: &GrandSlamCredentials,
    ) -> Result<()> {
        if credentials.idms_token.is_empty() {
            return Err(Error::Authentication(
                "GrandSlam omitted the token required for 2FA".into(),
            ));
        }
        let (method, url, body) = match (factor, code) {
            (SecondFactor::TrustedDevice, None) => (
                "GET",
                "https://gsa.apple.com/auth/verify/trusteddevice",
                Vec::new(),
            ),
            (SecondFactor::TrustedDevice, Some(_)) => (
                "GET",
                "https://gsa.apple.com/grandslam/GsService2/validate",
                Vec::new(),
            ),
            (SecondFactor::Sms, None) => (
                "PUT",
                "https://gsa.apple.com/auth/verify/phone",
                serde_json::to_vec(&serde_json::json!({"phoneNumber":{"id":1},"mode":"sms"}))?,
            ),
            (SecondFactor::Sms, Some(code)) => (
                "POST",
                "https://gsa.apple.com/auth/verify/phone/securitycode",
                serde_json::to_vec(
                    &serde_json::json!({"phoneNumber":{"id":1},"mode":"sms","securityCode":{"code":code}}),
                )?,
            ),
        };
        let mut headers = vec![
            (
                "Content-Type".into(),
                if factor == SecondFactor::Sms {
                    "application/json".into()
                } else {
                    "text/x-xml-plist".into()
                },
            ),
            ("User-Agent".into(), "Xcode".into()),
            ("Accept".into(), "text/x-xml-plist".into()),
            ("Accept-Language".into(), "en-us".into()),
            (
                "X-Apple-Identity-Token".into(),
                STANDARD.encode(format!("{}:{}", credentials.adsid, credentials.idms_token)),
            ),
            ("X-Apple-App-Info".into(), "com.apple.gs.xcode.auth".into()),
            ("X-Xcode-Version".into(), "11.2 (11B41)".into()),
            ("X-Mme-Client-Info".into(), GSA_CLIENT_INFO.into()),
        ];
        headers.extend(identity_headers(&self.anisette, &self.device).await?);
        if let Some(code) = code
            && factor == SecondFactor::TrustedDevice
        {
            headers.push(("security-code".into(), code.into()));
        }
        let response = self.send(method, url, headers, body).await?;
        if code.is_some() && factor == SecondFactor::TrustedDevice && !response.is_empty() {
            let value = parse_plist(&response)?;
            if nested(&value, &["ec"]).and_then(integer_value).unwrap_or(0) != 0 {
                return Err(Error::Authentication(
                    nested_string(&value, &["em"])
                        .unwrap_or("second-factor code rejected")
                        .into(),
                ));
            }
        }
        if code.is_some() && factor == SecondFactor::Sms && !response.is_empty() {
            let value: serde_json::Value = serde_json::from_slice(&response)?;
            if value.get("success").and_then(serde_json::Value::as_bool) == Some(false) {
                return Err(Error::Authentication("second-factor code rejected".into()));
            }
        }
        Ok(())
    }

    async fn icloud_headers(&self) -> Result<Vec<(String, String)>> {
        let mut headers = vec![
            ("User-Agent".into(), ICLOUD_USER_AGENT.into()),
            ("X-Mme-Client-Info".into(), ICLOUD_CLIENT_INFO.into()),
            ("Accept".into(), "*/*".into()),
        ];
        headers.extend(identity_headers(&self.anisette, &self.device).await?);
        Ok(headers)
    }

    async fn send(
        &self,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let response = self
            .transport
            .send(HttpRequest {
                method: method.into(),
                url: url.into(),
                headers,
                body,
            })
            .await?;
        if !(200..300).contains(&response.status) {
            return Err(Error::Authentication(format!(
                "Apple account endpoint returned HTTP {}",
                response.status
            )));
        }
        Ok(response.body)
    }
}

fn dictionary<const N: usize>(entries: [(&str, Value); N]) -> Dictionary {
    entries
        .into_iter()
        .map(|(k, v)| (String::from(k), v))
        .collect()
}

fn plist_bytes(value: Value) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    value
        .to_writer_xml(&mut body)
        .map_err(|error| Error::Authentication(error.to_string()))?;
    Ok(body)
}

fn parse_plist(body: &[u8]) -> Result<Value> {
    Value::from_reader(Cursor::new(body)).map_err(|error| Error::Authentication(error.to_string()))
}

fn required_dict(value: &Value) -> Result<&Dictionary> {
    value
        .as_dictionary()
        .ok_or_else(|| Error::Authentication("Apple returned a malformed plist".into()))
}

fn required<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    required_dict(value)?
        .get(key)
        .ok_or_else(|| Error::Authentication(format!("Apple response omitted {key}")))
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    required(value, key)?
        .as_string()
        .ok_or_else(|| Error::Authentication(format!("Apple response field {key} is not a string")))
}

fn data<'a>(value: &'a Value, key: &str) -> Result<&'a [u8]> {
    required(value, key)?
        .as_data()
        .ok_or_else(|| Error::Authentication(format!("Apple response field {key} is not data")))
}

fn integer(value: &Value, key: &str) -> Result<i64> {
    integer_value(required(value, key)?).ok_or_else(|| {
        Error::Authentication(format!("Apple response field {key} is not an integer"))
    })
}

fn nested<'a>(mut value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    for key in path {
        value = value.as_dictionary()?.get(key)?;
    }
    Some(value)
}

fn nested_string<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    nested(value, path)?.as_string()
}

fn string_any(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        let value = nested(value, &[*key])?;
        value
            .as_string()
            .map(str::to_owned)
            .or_else(|| integer_value(value).map(|n| n.to_string()))
    })
}

fn value_integer(dictionary: &Dictionary, key: &str) -> Option<i64> {
    integer_value(dictionary.get(key)?)
}

fn integer_value(value: &Value) -> Option<i64> {
    value.as_signed_integer().or_else(|| {
        value
            .as_unsigned_integer()
            .and_then(|n| i64::try_from(n).ok())
    })
}

fn string_map(value: &Value) -> BTreeMap<String, String> {
    value
        .as_dictionary()
        .into_iter()
        .flatten()
        .filter_map(|(key, value)| value.as_string().map(|value| (key.clone(), value.into())))
        .collect()
}

fn check_status(value: &Value, operation: &str) -> Result<()> {
    let status = nested(value, &["Status"]);
    let code = status
        .and_then(Value::as_dictionary)
        .and_then(|d| value_integer(d, "ec"));
    if code.unwrap_or(0) != 0 {
        let message = status
            .and_then(|v| nested_string(v, &["em"]))
            .unwrap_or("unknown error");
        return Err(Error::Authentication(format!(
            "{operation} failed ({}): {message}",
            code.unwrap_or(-1)
        )));
    }
    Ok(())
}

fn basic(user: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{secret}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_strings_and_integer_identifiers() {
        let value = Value::Dictionary(dictionary([
            ("DsPrsId", Value::Integer(1234.into())),
            (
                "tokens",
                Value::Dictionary(dictionary([(
                    "cloudKitToken",
                    Value::String("token".into()),
                )])),
            ),
        ]));
        assert_eq!(
            string_any(&value, &["adsid", "DsPrsId"]).as_deref(),
            Some("1234")
        );
        assert_eq!(
            string_map(nested(&value, &["tokens"]).unwrap())["cloudKitToken"],
            "token"
        );
    }
}
