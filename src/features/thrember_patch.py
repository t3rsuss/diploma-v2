import io

import thrember.features as tf
from signify.authenticode import SignedPEFile


def _raw_features(self, bytez, pe):
    if pe is None:
        return {}

    raw_obj = {
        "num_certs": 0,
        "self_signed": 0,
        "empty_program_name": 0,
        "no_countersigner": 0,
        "parse_error": 0,
        "chain_max_depth": 0,
        "latest_signing_time": 0,
        "signing_time_diff": 0,
    }
    try:
        signed_pe = SignedPEFile(io.BytesIO(bytez))
        for signed_data in signed_pe.iter_signed_datas():
            raw_obj["num_certs"] += 1
            if signed_data.signer_info.program_name is None:
                raw_obj["empty_program_name"] = 1

            countersigner = signed_data.signer_info.countersigner
            if countersigner is not None:
                signing_time = countersigner.signing_time.timestamp()
                if signing_time >= raw_obj["latest_signing_time"]:
                    raw_obj["latest_signing_time"] = signing_time
                raw_obj["signing_time_diff"] = signing_time - pe.FILE_HEADER.TimeDateStamp
            else:
                raw_obj["no_countersigner"] = 1

            certs = list(signed_data.certificates)
            if len(certs) > raw_obj["chain_max_depth"]:
                raw_obj["chain_max_depth"] = len(certs)
            for cert in certs[:-1]:
                if cert.issuer == cert.subject:
                    raw_obj["self_signed"] = 1
    except Exception:
        raw_obj["parse_error"] = 1
    return raw_obj


def apply():
    tf.AuthenticodeSignature.raw_features = _raw_features