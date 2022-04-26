/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/

// #include "spdm_emu.h"
#include <library/spdm_transport_mctp_lib.h>

#define SPDM_BLK_APP_TAMPER   0x01
#define SPDM_BLK_APP_MSG      0x02

#define SOCKET_TRANSPORT_TYPE_MCTP 0x01
#define SOCKET_TRANSPORT_TYPE_PCI_DOE 0x02

uint32 m_use_transport_layer = SOCKET_TRANSPORT_TYPE_MCTP;

uint8 m_use_version = SPDM_MESSAGE_VERSION_11;
uint8 m_use_secured_message_version = SPDM_MESSAGE_VERSION_11;
uint32 m_use_requester_capability_flags =
	(0 |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /* conflict with SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP */
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
	 // SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP | /* conflict with SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP */
	 0);
uint32 m_use_responder_capability_flags =
	(0 | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP |
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP | /* conflict with SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP */
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
	 // SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG | /* conflict with SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG */
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG | /* conflict with SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG */
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP |
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
	 // SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER | /* conflict with SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT */
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT | /* conflict with SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER */
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP |
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP |
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP |
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
	 // SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP | /* conflict with SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP */
	 0);

uint32 m_use_capability_flags = 0;
/*
  0
  1
*/
uint8 m_use_basic_mut_auth = 1;
/*
  0
  SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED,
  SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST,
  SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS
*/
uint8 m_use_mut_auth =
	SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST;
/*
  SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
  SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH,
  SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH
*/
uint8 m_use_measurement_summary_hash_type =
	SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH;
/*
  SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS, // one by one
  SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS
*/
uint8 m_use_measurement_operation =
	SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS;
uint8 m_use_slot_id = 0;
uint8 m_use_slot_count = 3;

/*
  SPDM_KEY_UPDATE_ACTION_REQUESTER
  SPDM_KEY_UPDATE_ACTION_RESPONDER
  SPDM_KEY_UPDATE_ACTION_ALL
*/
spdm_key_update_action_t m_use_key_update_action = SPDM_KEY_UPDATE_ACTION_ALL;

uint32 m_use_hash_algo;
uint32 m_use_measurement_hash_algo;
uint32 m_use_asym_algo;
uint16 m_use_req_asym_algo;

/*
  SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
*/
uint8 m_support_measurement_spec =
	SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
/*
  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512,
  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384,
  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256,
  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512,
  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384,
  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY,
*/
uint32 m_support_measurement_hash_algo =
	SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512 |
	SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384;
/*
  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,
  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
*/
uint32 m_support_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
			     SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
/*
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
*/
uint32 m_support_asym_algo =
	SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
	SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
/*
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
*/
uint16 m_support_req_asym_algo =
	SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
	SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
	SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
	SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
/*
  SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096,
  SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072,
  SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048,
  SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1,
  SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1,
  SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1,
*/
uint16 m_support_dhe_algo = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
			    SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
			    SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072 |
			    SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048;
/*
  SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM,
  SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM,
  SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305,
*/
uint16 m_support_aead_algo =
	SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
	SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305;
/*
  SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH,
*/
uint16 m_support_key_schedule_algo = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;


#define EXE_MODE_SHUTDOWN 0
#define EXE_MODE_CONTINUE 1
// extern uint32 m_exe_mode;

#define EXE_CONNECTION_VERSION_ONLY 0x1
#define EXE_CONNECTION_DIGEST 0x2
#define EXE_CONNECTION_CERT 0x4
#define EXE_CONNECTION_CHAL 0x8
#define EXE_CONNECTION_MEAS 0x10
// extern uint32 m_exe_connection;

#define EXE_SESSION_KEY_EX 0x1
#define EXE_SESSION_PSK 0x2
#define EXE_SESSION_NO_END 0x4
#define EXE_SESSION_KEY_UPDATE 0x8
#define EXE_SESSION_HEARTBEAT 0x10
#define EXE_SESSION_MEAS 0x20
// extern uint32 m_exe_session;

uint32 m_exe_mode = EXE_MODE_SHUTDOWN;

uint32 m_exe_connection = (0 |
         // EXE_CONNECTION_VERSION_ONLY |
         EXE_CONNECTION_DIGEST | EXE_CONNECTION_CERT |
         EXE_CONNECTION_CHAL | EXE_CONNECTION_MEAS | 0);

uint32 m_exe_session =
  (0 | EXE_SESSION_KEY_EX | EXE_SESSION_PSK |
   // EXE_SESSION_NO_END |
   EXE_SESSION_KEY_UPDATE | EXE_SESSION_HEARTBEAT | EXE_SESSION_MEAS | 0);

boolean read_input_file(IN char8 *file_name, OUT void **file_data,
      OUT uintn *file_size)
{
  FILE *fp_in;
  uintn temp_result;

  if ((fp_in = fopen(file_name, "rb")) == NULL) {
    printf("Unable to open file %s\n", file_name);
    *file_data = NULL;
    return FALSE;
  }

  fseek(fp_in, 0, SEEK_END);
  *file_size = ftell(fp_in);

  *file_data = (void *)malloc(*file_size);
  if (NULL == *file_data) {
    printf("No sufficient memory to allocate %s\n", file_name);
    fclose(fp_in);
    return FALSE;
  }

  fseek(fp_in, 0, SEEK_SET);
  temp_result = fread(*file_data, 1, *file_size, fp_in);
  if (temp_result != *file_size) {
    printf("Read input file error %s", file_name);
    free((void *)*file_data);
    fclose(fp_in);
    return FALSE;
  }

  fclose(fp_in);

  return TRUE;
}

void dump_hex_str(IN uint8 *buffer, IN uintn buffer_size)
{
  uintn index;

  for (index = 0; index < buffer_size; index++) {
    printf("%02x", buffer[index]);
  }
}


uint8 ts[10] = {0};

boolean spdm_measurement_collection(IN uint8 measurement_specification,
           IN uint32 measurement_hash_algo,
           OUT uint8 *device_measurement_count,
           OUT void *device_measurement,
           IN OUT uintn *device_measurement_size)
{

  spdm_measurement_block_dmtf_t *MeasurementBlock;
  uintn hash_size;
  uint8 index;
  uint8 data[MEASUREMENT_MANIFEST_SIZE];
  uintn total_size;

  ASSERT(measurement_specification ==
         SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF);
  if (measurement_specification !=
      SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF) {
    return FALSE;
  }

  hash_size = spdm_get_measurement_hash_size(measurement_hash_algo);
  ASSERT(hash_size != 0);

  *device_measurement_count = MEASUREMENT_BLOCK_NUMBER;
  if (hash_size != 0xFFFFFFFF) {
    total_size =
      (MEASUREMENT_BLOCK_NUMBER - 1) *
        (sizeof(spdm_measurement_block_dmtf_t) +
         hash_size) +
      (sizeof(spdm_measurement_block_dmtf_t) + sizeof(data));
  } else {
    total_size =
      (MEASUREMENT_BLOCK_NUMBER - 1) *
        (sizeof(spdm_measurement_block_dmtf_t) +
         sizeof(data)) +
      (sizeof(spdm_measurement_block_dmtf_t) + sizeof(data));
  }
  ASSERT(*device_measurement_size >= total_size);
  *device_measurement_size = total_size;

  MeasurementBlock = device_measurement;
  for (index = 0; index < MEASUREMENT_BLOCK_NUMBER; index++) {
    MeasurementBlock->Measurement_block_common_header.index =
      index + 1;
    MeasurementBlock->Measurement_block_common_header
      .measurement_specification =
      SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    if ((index < 4) && (hash_size != 0xFFFFFFFF)) {
      MeasurementBlock->Measurement_block_dmtf_header
        .dmtf_spec_measurement_value_type = index;
      MeasurementBlock->Measurement_block_dmtf_header
        .dmtf_spec_measurement_value_size =
        (uint16)hash_size;
    } else {
      MeasurementBlock->Measurement_block_dmtf_header
        .dmtf_spec_measurement_value_type =
        index |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
      MeasurementBlock->Measurement_block_dmtf_header
        .dmtf_spec_measurement_value_size =
        (uint16)sizeof(data);
    }
    MeasurementBlock->Measurement_block_common_header
      .measurement_size =
      (uint16)(sizeof(spdm_measurement_block_dmtf_header_t) +
         MeasurementBlock->Measurement_block_dmtf_header
           .dmtf_spec_measurement_value_size);
    set_mem(data, sizeof(data), (uint8)(index + 1 + ts[index]));
    if ((index < 4) && (hash_size != 0xFFFFFFFF)) {
      spdm_measurement_hash_all(
        measurement_hash_algo, data, sizeof(data),
        (void *)(MeasurementBlock + 1));
      MeasurementBlock =
        (void *)((uint8 *)MeasurementBlock +
           sizeof(spdm_measurement_block_dmtf_t) +
           hash_size);
    } else {
      copy_mem((void *)(MeasurementBlock + 1), data,
         sizeof(data));
      MeasurementBlock =
        (void *)((uint8 *)MeasurementBlock +
           sizeof(spdm_measurement_block_dmtf_t) +
           sizeof(data));
    }
  }

  return TRUE;
}