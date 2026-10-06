use serde::{de::Error, Deserialize, Deserializer, Serializer};

pub fn serialize<S, T>(v: &T, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    s.serialize_str(&hex::encode(v.as_ref()))
}

pub fn deserialize<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: TryFrom<Vec<u8>>,
{
    let s = String::deserialize(d)?;
    let v = hex::decode(&s).map_err(D::Error::custom)?;
    T::try_from(v).map_err(|_| D::Error::custom("wrong length"))
}
