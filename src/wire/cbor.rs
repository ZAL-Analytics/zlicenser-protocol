use serde::{de::DeserializeOwned, Serialize};

use crate::error::Error;

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).map_err(|e| Error::Encode(e.to_string()))?;
    Ok(buf)
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    ciborium::de::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))
}
