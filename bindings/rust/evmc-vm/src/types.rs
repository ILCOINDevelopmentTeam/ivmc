use ivmc_sys as ffi;

/// IVMC address
pub type Address = ffi::ivmc_address;

/// IVMC 32 bytes value (used for hashes)
pub type Bytes32 = ffi::ivmc_bytes32;

/// IVMC big-endian 256-bit integer
pub type Uint256 = ffi::ivmc_uint256be;

/// IVMC call kind.
pub type MessageKind = ffi::ivmc_call_kind;

/// IVMC message (call) flags.
pub type MessageFlags = ffi::ivmc_flags;

/// IVMC status code.
pub type StatusCode = ffi::ivmc_status_code;

/// IVMC access status.
pub type AccessStatus = ffi::ivmc_access_status;

/// IVMC storage status.
pub type StorageStatus = ffi::ivmc_storage_status;

/// IVMC VM revision.
pub type Revision = ffi::ivmc_revision;

#[cfg(test)]
mod tests {
    use super::*;

    // These tests check for Default, PartialEq and Clone traits.
    #[test]
    fn address_smoke_test() {
        let a = ffi::ivmc_address::default();
        let b = Address::default();
        assert_eq!(a.clone(), b.clone());
    }

    #[test]
    fn bytes32_smoke_test() {
        let a = ffi::ivmc_bytes32::default();
        let b = Bytes32::default();
        assert_eq!(a.clone(), b.clone());
    }

    #[test]
    fn uint26be_smoke_test() {
        let a = ffi::ivmc_uint256be::default();
        let b = Uint256::default();
        assert_eq!(a.clone(), b.clone());
    }

    #[test]
    fn message_kind() {
        assert_eq!(MessageKind::IVMC_CALL, ffi::ivmc_call_kind::IVMC_CALL);
        assert_eq!(
            MessageKind::IVMC_CALLCODE,
            ffi::ivmc_call_kind::IVMC_CALLCODE
        );
        assert_eq!(
            MessageKind::IVMC_DELEGATECALL,
            ffi::ivmc_call_kind::IVMC_DELEGATECALL
        );
        assert_eq!(MessageKind::IVMC_CREATE, ffi::ivmc_call_kind::IVMC_CREATE);
    }

    #[test]
    fn message_flags() {
        assert_eq!(MessageFlags::IVMC_STATIC, ffi::ivmc_flags::IVMC_STATIC);
    }

    #[test]
    fn status_code() {
        assert_eq!(
            StatusCode::IVMC_SUCCESS,
            ffi::ivmc_status_code::IVMC_SUCCESS
        );
        assert_eq!(
            StatusCode::IVMC_FAILURE,
            ffi::ivmc_status_code::IVMC_FAILURE
        );
    }

    #[test]
    fn access_status() {
        assert_eq!(
            AccessStatus::IVMC_ACCESS_COLD,
            ffi::ivmc_access_status::IVMC_ACCESS_COLD
        );
        assert_eq!(
            AccessStatus::IVMC_ACCESS_WARM,
            ffi::ivmc_access_status::IVMC_ACCESS_WARM
        );
    }

    #[test]
    fn storage_status() {
        assert_eq!(
            StorageStatus::IVMC_STORAGE_UNCHANGED,
            ffi::ivmc_storage_status::IVMC_STORAGE_UNCHANGED
        );
        assert_eq!(
            StorageStatus::IVMC_STORAGE_MODIFIED,
            ffi::ivmc_storage_status::IVMC_STORAGE_MODIFIED
        );
    }

    #[test]
    fn revision() {
        assert_eq!(Revision::IVMC_FRONTIER, ffi::ivmc_revision::IVMC_FRONTIER);
        assert_eq!(Revision::IVMC_ISTANBUL, ffi::ivmc_revision::IVMC_ISTANBUL);
    }
}
