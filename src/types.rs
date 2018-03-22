//! Error types

use std::{error, fmt};
use std::io;
use std::num;
use std::string;
use bech32;
use secp256k1;

/// Result of vector base conversion
pub type ConvertResult = Result<Vec<u8>, Error>;

/// Error types
#[derive(Debug)]
pub enum Error {
    /// Invalid parameter.
    InvalidParameter(String),
    /// Input value exceeds "from bits" size.
    InvalidInputValue(u8),
    /// Invalid value.
    InvalidValue(String),
    /// Invalid padding values in data.
    InvalidPadding,
    /// Invalid input length.
    InvalidLength(String),
    /// Wraps an io error produced when reading or writing.
    IOErr(io::Error),
    /// Wraps parse float error.
    ParseFloatErr(num::ParseFloatError),
    /// Wraps parse int error.
    ParseIntErr(num::ParseIntError),
    /// Wraps string from utf8 error.
    FromUTF8Err(string::FromUtf8Error),
    /// Wraps bech32 error.
    Bech32Err(bech32::Error),
    /// Wraps secp256k1 error.
    SignatureError(secp256k1::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidParameter(ref e) => write!(f, "{}", e),
            Error::InvalidInputValue(e) => write!(f, "invalid input value ({})", e),
            Error::InvalidValue(ref e) => write!(f, "{}", e),
            Error::InvalidPadding => write!(f, "invalid padding"),
            Error::InvalidLength(ref e) => write!(f, "{}", e),
            Error::IOErr(ref e) => write!(f, "{}", e),
            Error::ParseFloatErr(ref e) => write!(f, "{}", e),
            Error::ParseIntErr(ref e) => write!(f, "{}", e),
            Error::FromUTF8Err(ref e) => write!(f, "{}", e),
            Error::Bech32Err(ref e) => write!(f, "{}", e),
            Error::SignatureError(ref e) => write!(f, "{:?}", e),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::InvalidParameter(ref e) => e,
            Error::InvalidInputValue(_) => "invalid input value",
            Error::InvalidValue(ref e) => e,
            Error::InvalidPadding => "invalid padding",
            Error::InvalidLength(ref e) => e,
            Error::IOErr(ref e) => error::Error::description(e),
            Error::ParseFloatErr(ref e) => error::Error::description(e),
            Error::ParseIntErr(ref e) => error::Error::description(e),
            Error::FromUTF8Err(ref e) => error::Error::description(e),
            Error::Bech32Err(ref e) => error::Error::description(e),
            Error::SignatureError(ref e) => match *e {
                secp256k1::Error::InvalidSignature => "invalid signature",
                secp256k1::Error::InvalidPublicKey => "invalid public key",
                secp256k1::Error::InvalidSecretKey => "invalid secret key",
                secp256k1::Error::InvalidRecoveryId => "invalid recovery id",
                secp256k1::Error::InvalidMessage => "invalid message",
            },
        }
    }
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::IOErr(ref e) => Some(e),
            Error::ParseFloatErr(ref e) => Some(e),
            Error::ParseIntErr(ref e) => Some(e),
            Error::FromUTF8Err(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IOErr(e)
    }
}

impl From<num::ParseFloatError> for Error {
    fn from(e: num::ParseFloatError) -> Error {
        Error::ParseFloatErr(e)
    }
}

impl From<num::ParseIntError> for Error {
    fn from(e: num::ParseIntError) -> Error {
        Error::ParseIntErr(e)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(e: string::FromUtf8Error) -> Error {
        Error::FromUTF8Err(e)
    }
}

impl From<bech32::Error> for Error {
    fn from(e: bech32::Error) -> Error {
        Error::Bech32Err(e)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::SignatureError(e)
    }
}
