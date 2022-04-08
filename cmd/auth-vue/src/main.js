/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import { createApp } from 'vue';
import App from '@/App.vue';
import router from '@/router';
import { setupI18n } from '@/plugins/i18n';
import '@/tailwind.css';
import TheToastNotification from '@/components/TheToastNotification.vue';

const i18n = setupI18n();

const app = createApp({
  ...App,
});

app.use(router);
app.use(i18n);
app.component('TheToastNotification', TheToastNotification);

app.mount('#app');
