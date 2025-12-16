import json
import unittest
import hmac
import hashlib
import client_encryption.jwe_encryption as to_test
from client_encryption.encryption_exception import EncryptionError
from client_encryption.jwe_encryption_config import JweEncryptionConfig
from tests import get_mastercard_config_for_test


class JweEncryptionTest(unittest.TestCase):

    def setUp(self):
        self._config = JweEncryptionConfig(get_mastercard_config_for_test())
        self._config._paths["$"]._to_encrypt = {"$": "$"}
        self._config._paths["$"]._to_decrypt = {"encryptedValue": "$"}

    def test_encrypt_payload_should_be_able_to_be_decrypted(self):
        payload = {
            "data": {
                "field1": "value1",
                "field2": "value2"
            }
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)
        decrypted_payload = to_test.decrypt_payload(encrypted_payload, self._config)
        self.assertDictEqual(payload, decrypted_payload)

    def test_encrypt_payload_should_be_able_to_decrypt_empty_json(self):
        payload = {}

        encrypted_payload = to_test.encrypt_payload(payload, self._config)
        decrypted_payload = to_test.decrypt_payload(encrypted_payload, self._config)
        self.assertDictEqual(payload, decrypted_payload)

    def test_encrypt_payload_should_be_able_to_decrypt_root_arrays(self):
        payload = [
            {
                'field1': 'field2'
            }
        ]

        encrypted_payload = to_test.encrypt_payload(payload, self._config)
        decrypted_payload = to_test.decrypt_payload(encrypted_payload, self._config)
        self.assertListEqual(payload, decrypted_payload)

    def test_encrypt_payload_with_multiple_encryption_paths(self):
        self._config._paths["$"]._to_encrypt = {"data1": "encryptedData1", "data2": "encryptedData2"}
        self._config._paths["$"]._to_decrypt = {"encryptedData1": "data1", "encryptedData2": "data2"}

        payload = {
            "data1": {
                "field1": "value1",
                "field2": "value2"
            },
            "data2": {
                "field3": "value3",
                "field4": "value4"
            }
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)

        self.assertNotIn("data1", encrypted_payload)
        self.assertNotIn("data2", encrypted_payload)

        decrypted_payload = to_test.decrypt_payload(encrypted_payload, self._config)
        self.assertDictEqual(payload, decrypted_payload)

    def test_decrypt_payload_should_decrypt_aes128gcm_payload(self):
        encrypted_payload = {
            "encryptedValue": "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.WtvYljbsjdEv-Ttxx1p6PgyIrOsLpj1FMF9NQNhJUAHlKchAo5QImgEgIdgJE7HC2KfpNcHiQVqKKZq_y201FVzpicDkNzlPJr5kIH4Lq-oC5iP0agWeou9yK5vIxFRP__F_B8HSuojBJ3gDYT_KdYffUIHkm_UysNj4PW2RIRlafJ6RKYanVzk74EoKZRG7MIr3pTU6LIkeQUW41qYG8hz6DbGBOh79Nkmq7Oceg0ZwCn1_MruerP-b15SGFkuvOshStT5JJp7OOq82gNAOkMl4fylEj2-vADjP7VSK8GlqrA7u9Tn-a4Q28oy0GOKr1Z-HJgn_CElknwkUTYsWbg.PKl6_kvZ4_4MjmjW.AH6pGFkn7J49hBQcwg.zdyD73TcuveImOy4CRnVpw"
        }

        decrypted_payload = {"foo": "bar"}

        payload = to_test.decrypt_payload(encrypted_payload, self._config)
        self.assertNotIn("encryptedValue", payload)
        self.assertDictEqual(decrypted_payload, payload)

    def test_decrypt_payload_should_decrypt_aes192gcm_payload(self):
        encrypted_payload = {
            "encryptedValue": "eyJlbmMiOiJBMTkyR0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.FWC8PVaZoR2TRKwKO4syhSJReezVIvtkxU_yKh4qODNvlVr8t8ttvySJ-AjM8xdI6vNyIg9jBMWASG4cE49jT9FYuQ72fP4R-Td4vX8wpB8GonQj40yLqZyfRLDrMgPR20RcQDW2ThzLXsgI55B5l5fpwQ9Nhmx8irGifrFWOcJ_k1dUSBdlsHsYxkjRKMENu5x4H6h12gGZ21aZSPtwAj9msMYnKLdiUbdGmGG_P8a6gPzc9ih20McxZk8fHzXKujjukr_1p5OO4o1N4d3qa-YI8Sns2fPtf7xPHnwi1wipmCC6ThFLU80r3173RXcpyZkF8Y3UacOS9y1f8eUfVQ.JRE7kZLN4Im1Rtdb.eW_lJ-U330n0QHqZnQ._r5xYVvMCrvICwLz4chjdw"
        }

        decrypted_payload = {"foo": "bar"}

        payload = to_test.decrypt_payload(encrypted_payload, self._config)
        self.assertNotIn("encryptedValue", payload)
        self.assertDictEqual(decrypted_payload, payload)

    def test_decrypt_payload_should_decrypt_aes256gcm_payload(self):
        encrypted_payload = {
            "encryptedValue": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.8c6vxeZOUBS8A9SXYUSrRnfl1ht9xxciB7TAEv84etZhQQ2civQKso-htpa2DWFBSUm-UYlxb6XtXNXZxuWu-A0WXjwi1K5ZAACc8KUoYnqPldEtC9Q2bhbQgc_qZF_GxeKrOZfuXc9oi45xfVysF_db4RZ6VkLvY2YpPeDGEMX_nLEjzqKaDz_2m0Ae_nknr0p_Nu0m5UJgMzZGR4Sk1DJWa9x-WJLEyo4w_nRDThOjHJshOHaOU6qR5rdEAZr_dwqnTHrjX9Qm9N9gflPGMaJNVa4mvpsjz6LJzjaW3nJ2yCoirbaeJyCrful6cCiwMWMaDMuiBDPKa2ovVTy0Sw.w0Nkjxl0T9HHNu4R.suRZaYu6Ui05Z3-vsw.akknMr3Dl4L0VVTGPUszcA"
        }

        decrypted_payload = {"foo": "bar"}

        payload = to_test.decrypt_payload(encrypted_payload, self._config)
        self.assertNotIn("encryptedValue", payload)
        self.assertDictEqual(decrypted_payload, payload)

    def test_decrypt_payload_should_decrypt_cbc_payload(self):
        encrypted_payload = {
            "encryptedValue": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.2GzZlB3scifhqlzIV2Rxk1TwiWL35e0AtcI9MFusG9jv9zGrJ8BapJx73PlFu69S0IAR7hXpqwzD7-UzmHUdrxB7izbMm9TNDpznHIuTaJWSRngD5Zui_rUXETL0GJG8dERx7IngqTltfzZanhDnjDNfKaowD6pFSEVN-Ff-pTeJqLMPs5504DtnYGD_uhQjvFmREIBgQTGEINzT88PXwLTAVBbWbAad_I-4Q12YwW_Y4yqmARCMTRWP-ixMrlSWCJlh6hz-biEotWNwGvp2pdhdiEP2VSvvUKHd7IngMWcMozOcoZQ1n18kWiFvt90fzNXSmzTjyGYSWUsa_mVouA.aX5mOSiXtilwYPFeTUFN_A.ZyAY79BAjG-QMQIhesj9bQ.TPZ2VYWdTLopCNkvMqUyuQ"
        }

        decrypted_payload = {"foo": "bar"}

        payload = to_test.decrypt_payload(encrypted_payload, self._config)
        self.assertNotIn("encryptedValue", payload)
        self.assertDictEqual(decrypted_payload, payload)

    def test_decrypt_payload_should_verify_hmac_when_enabled(self):
        config = self.__build_config_with_hmac(True)

        encrypted_payload = {
            "encryptedValue": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.2GzZlB3scifhqlzIV2Rxk1TwiWL35e0AtcI9MFusG9jv9zGrJ8BapJx73PlFu69S0IAR7hXpqwzD7-UzmHUdrxB7izbMm9TNDpznHIuTaJWSRngD5Zui_rUXETL0GJG8dERx7IngqTltfzZanhDnjDNfKaowD6pFSEVN-Ff-pTeJqLMPs5504DtnYGD_uhQjvFmREIBgQTGEINzT88PXwLTAVBbWbAad_I-4Q12YwW_Y4yqmARCMTRWP-ixMrlSWCJlh6hz-biEotWNwGvp2pdhdiEP2VSvvUKHd7IngMWcMozOcoZQ1n18kWiFvt90fzNXSmzTjyGYSWUsa_mVouA.aX5mOSiXtilwYPFeTUFN_A.ZyAY79BAjG-QMQIhesj9bQ.TPZ2VYWdTLopCNkvMqUyuQ"
        }

        decrypted_payload = {"foo": "bar"}

        payload = to_test.decrypt_payload(encrypted_payload, config)
        self.assertDictEqual(decrypted_payload, payload)

    def test_decrypt_payload_should_fail_when_hmac_invalid_and_enabled(self):
        config = self.__build_config_with_hmac(True)

        encrypted_value = "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.2GzZlB3scifhqlzIV2Rxk1TwiWL35e0AtcI9MFusG9jv9zGrJ8BapJx73PlFu69S0IAR7hXpqwzD7-UzmHUdrxB7izbMm9TNDpznHIuTaJWSRngD5Zui_rUXETL0GJG8dERx7IngqTltfzZanhDnjDNfKaowD6pFSEVN-Ff-pTeJqLMPs5504DtnYGD_uhQjvFmREIBgQTGEINzT88PXwLTAVBbWbAad_I-4Q12YwW_Y4yqmARCMTRWP-ixMrlSWCJlh6hz-biEotWNwGvp2pdhdiEP2VSvvUKHd7IngMWcMozOcoZQ1n18kWiFvt90fzNXSmzTjyGYSWUsa_mVouA.aX5mOSiXtilwYPFeTUFN_A.ZyAY79BAjG-QMQIhesj9bQ.TPZ2VYWdTLopCNkvMqUyuQ"
        tampered_parts = encrypted_value.split(".")
        tampered_parts[-1] = tampered_parts[-1][:-1] + ("A" if tampered_parts[-1][-1] != "A" else "B")
        tampered_payload = {"encryptedValue": ".".join(tampered_parts)}

        with self.assertRaises(EncryptionError):
            to_test.decrypt_payload(tampered_payload, config)

    def test_decrypt_payload_should_skip_hmac_when_disabled(self):
        config = self.__build_config_with_hmac(False)

        encrypted_value = "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.2GzZlB3scifhqlzIV2Rxk1TwiWL35e0AtcI9MFusG9jv9zGrJ8BapJx73PlFu69S0IAR7hXpqwzD7-UzmHUdrxB7izbMm9TNDpznHIuTaJWSRngD5Zui_rUXETL0GJG8dERx7IngqTltfzZanhDnjDNfKaowD6pFSEVN-Ff-pTeJqLMPs5504DtnYGD_uhQjvFmREIBgQTGEINzT88PXwLTAVBbWbAad_I-4Q12YwW_Y4yqmARCMTRWP-ixMrlSWCJlh6hz-biEotWNwGvp2pdhdiEP2VSvvUKHd7IngMWcMozOcoZQ1n18kWiFvt90fzNXSmzTjyGYSWUsa_mVouA.aX5mOSiXtilwYPFeTUFN_A.ZyAY79BAjG-QMQIhesj9bQ.TPZ2VYWdTLopCNkvMqUyuQ"
        tampered_parts = encrypted_value.split(".")
        tampered_parts[-1] = tampered_parts[-1][:-1] + ("A" if tampered_parts[-1][-1] != "A" else "B")
        tampered_payload = {"encryptedValue": ".".join(tampered_parts)}

        payload = to_test.decrypt_payload(tampered_payload, config)
        self.assertEqual({"foo": "bar"}, payload)

    def test_decrypt_payload_should_fail_when_hmac_missing_and_enabled(self):
        config = self.__build_config_with_hmac(True)

        encrypted_value = "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.2GzZlB3scifhqlzIV2Rxk1TwiWL35e0AtcI9MFusG9jv9zGrJ8BapJx73PlFu69S0IAR7hXpqwzD7-UzmHUdrxB7izbMm9TNDpznHIuTaJWSRngD5Zui_rUXETL0GJG8dERx7IngqTltfzZanhDnjDNfKaowD6pFSEVN-Ff-pTeJqLMPs5504DtnYGD_uhQjvFmREIBgQTGEINzT88PXwLTAVBbWbAad_I-4Q12YwW_Y4yqmARCMTRWP-ixMrlSWCJlh6hz-biEotWNwGvp2pdhdiEP2VSvvUKHd7IngMWcMozOcoZQ1n18kWiFvt90fzNXSmzTjyGYSWUsa_mVouA.aX5mOSiXtilwYPFeTUFN_A.ZyAY79BAjG-QMQIhesj9bQ.TPZ2VYWdTLopCNkvMqUyuQ"
        missing_tag_payload = {"encryptedValue": ".".join(encrypted_value.split(".")[:-1])}

        with self.assertRaises(EncryptionError):
            to_test.decrypt_payload(missing_tag_payload, config)

    def test_split_cbc_keys_should_reject_invalid_length(self):
        with self.assertRaises(EncryptionError):
            to_test._split_cbc_keys(b"short-key")

    def test_compute_cbc_auth_tag_matches_reference(self):
        mac_key = b"\x01" * 16
        aad = b"header"
        iv = b"\x02" * 16
        cipher_text = b"\x03\x04"

        expected_tag = hmac.new(mac_key, aad + iv + cipher_text + (len(aad) * 8).to_bytes(8, "big"), hashlib.sha256).digest()[:16]
        computed_tag = to_test._compute_cbc_auth_tag(mac_key, aad, iv, cipher_text)

        self.assertEqual(expected_tag, computed_tag)

    def __build_config_with_hmac(self, enabled):
        json_conf = json.loads(get_mastercard_config_for_test())
        json_conf["enableCbcHmacVerification"] = enabled

        conf = JweEncryptionConfig(json_conf)
        conf._paths["$"]._to_encrypt = {"$": "$"}
        conf._paths["$"]._to_decrypt = {"encryptedValue": "$"}

        return conf
