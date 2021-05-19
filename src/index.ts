#!/usr/bin/env node

import axios from 'axios';
import inquirer from 'inquirer';
import { v4 as uuidv4 } from 'uuid';
import * as api from './api';

import constants from './constants';
import decryptTokens from './decrypt';
import getOtps from './otp';

// Inject axios defaults
axios.defaults.baseURL = constants.API_BASE_URL;
axios.defaults.headers.common['X-User-Agent'] = constants.USER_AGENT;
axios.defaults.headers.common['X-Authy-Device-App'] = constants.DEVICE_APP;
axios.defaults.params = {
  api_key: constants.API_KEY,
  locale: constants.LOCALE,
};

// Inject new RequestID for every request
axios.interceptors.request.use((config) => {
  // eslint-disable-next-line no-param-reassign
  config.headers['X-Authy-Request-ID'] = uuidv4();
  return config;
});

// Calculate moving factor correction with every request
let movingFactorCorrection = 0;
axios.interceptors.response.use((response) => {
  // SyncTimeSync.prototype.syncTime
  const serverTime = new Date(response.headers.date).getTime();
  movingFactorCorrection = Math.round((serverTime - new Date().getTime()) / 1000);

  return response;
});

async function run() {
  try {
    const { phoneNumber } = await inquirer.prompt<{ phoneNumber: string }>([
      {
        type: 'input',
        name: 'phoneNumber',
        message: 'Phone number followed by country code, eg. 48-700100100',
        validate: (value) => value.match(/^[0-9]+-[0-9]+$/) !== null || 'Please enter valid phone number',
      },
    ]);

    const deviceStatus = await api.getDeviceStatus(phoneNumber);
    if (deviceStatus.message !== 'active' || !deviceStatus.authy_id) {
      throw new Error('Account must be active to perform a backup');
    }

    const { authMethod } = await inquirer.prompt<{ authMethod: string }>([
      {
        type: 'list',
        name: 'authMethod',
        message: 'Authentication method',
        choices: [
          { name: 'SMS', value: 'sms' },
          { name: 'Call', value: 'call' },
          { name: 'Other device', value: 'push' },
        ],
      },
    ]);

    await api.createNewDeviceRequest(
      deviceStatus.authy_id,
      authMethod,
      constants.DEVICE_APP,
      constants.DEVICE_NAME,
    );

    const { pin } = await inquirer.prompt<{ pin: number }>([
      {
        type: 'password',
        name: 'pin',
        message: 'PIN code',
        mask: '*',
        validate: (value) => value.match(/^[0-9]+$/) !== null || 'Please enter valid PIN code',
      },
    ]);

    const { device } = await api.registerNewDevice(
      deviceStatus.authy_id,
      pin,
      constants.DEVICE_APP,
      constants.DEVICE_NAME,
    );

    const otps = getOtps(
      device.secret_seed,
      constants.OTP_LENGTH,
      constants.OTP_TIME_STEP,
      movingFactorCorrection,
    );

    const { authenticator_tokens: tokens } = await api.syncAuthenticatorApps(
      deviceStatus.authy_id,
      device.id,
      otps,
    );

    const { password } = await inquirer.prompt<{ password: string }>([
      {
        type: 'password',
        name: 'password',
        mask: '*',
        message: 'Master password (needed to unlock the backup)',
      },
    ]);

    const decryptedTokens = decryptTokens(tokens, password);

    console.log(decryptedTokens);
  } catch (err) {
    console.error(err.message);
  }
}

run();
