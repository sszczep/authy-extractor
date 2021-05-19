import axios from 'axios';
import forge from 'node-forge';
import { v4 as uuidv4 } from 'uuid';
import { AuthyRequestOtps } from './otp';

export interface DeviceStatusDTO {
  force_ott: boolean;
  message: string;
  devices_count?: number;
  authy_id?: number;
  success: boolean;
}

// RegistrationApi.prototype.getDeviceStatus
export async function getDeviceStatus(phoneNumber: string) {
  // Authy uses Fingerprint2 library, just generate random 32 char string
  // The device uuid is being used only once, hence defining it here
  const deviceUUID = uuidv4().split('-').join('');

  const { data } = await axios.get<DeviceStatusDTO>(`/json/users/${phoneNumber}/status`, {
    params: { uuid: deviceUUID },
  });

  return data;
}

export interface DeviceReqisterRequestDTO {
  message: string;
  request_id: string;
  approval_pin: number;
  provider?: any; // TODO: Determine the type
  success: boolean;
}

// RegistrationApi.prototype.createNewDeviceRequest
export async function createNewDeviceRequest(
  authyId: number,
  authMethod: string,
  deviceApp: string,
  deviceName: string,
) {
  // CryptoHelper.generateSalt
  // The signature is being used only once, hence defining it here
  const signature = forge.util.createBuffer(forge.random.getBytesSync(32)).toHex();

  const { data } = await axios.post<DeviceReqisterRequestDTO>(
    `/json/users/${authyId}/devices/registration/start`,
    null,
    {
      params: {
        via: authMethod,
        signature,
        device_app: deviceApp,
        device_name: deviceName,
      },
    },
  );

  return data;
}

export interface DeviceRegisterResponseDTO {
  device: {
    id: number;
    secret_seed: string;
    api_key: string;
    reinstall: boolean;
  };

  authy_id: number;
}

// RegistrationApi.prototype.registerNewDevice
export async function registerNewDevice(
  authyId: number,
  pin: number,
  deviceApp: string,
  deviceName: string,
) {
  const { data } = await axios.post<DeviceRegisterResponseDTO>(
    `json/users/${authyId}/devices/registration/complete`,
    null,
    {
      params: { pin, device_app: deviceApp, device_name: deviceName },
    },
  );

  return data;
}

export interface AuthenticatorTokenDTO {
  account_type: string;
  digits: number;
  encrypted_seed: string;
  issuer?: any; // TODO: Determine the type, probably string
  logo?: any; // TODO: Determine the type, probably string
  name: string;
  original_name?: any; // TODO: Determine the type, probably string
  password_timestamp: number;
  salt: string;
  unique_id: string;
}

export interface AuthenticatorAppsDTO {
  authenticator_tokens: AuthenticatorTokenDTO[];
  deleted: any[]; // TODO: Determine the type
  message: string;
  success: boolean;
}

// AppsApi.prototype.syncAuthenticatorApps
export async function syncAuthenticatorApps(
  authyId: number,
  deviceId: number,
  otps: AuthyRequestOtps,
) {
  const { data } = await axios.get<AuthenticatorAppsDTO>(
    `/json/users/${authyId}/authenticator_tokens`,
    {
      params: { apps: '', device_id: deviceId, ...otps },
    },
  );

  return data;
}
