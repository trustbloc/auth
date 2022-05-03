<!--
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
-->

<script setup>
import { ref, onMounted } from 'vue';
import axios from 'axios';
import TheToastNotification from '@/components/TheToastNotification.vue';
import IconLogo from '@/components/icons/IconLogo.vue';
import IconSpinner from '@/components/icons/IconSpinner.vue';
import { useI18n } from 'vue-i18n';

const loading = ref(true);
const providers = ref([]);
const systemError = ref(false);
const providerPopup = ref({ closed: false });
const { t, locale } = useI18n();

onMounted(async () => {
  try {
    const rawProviders = await axios.get('/oauth2/providers');
    providers.value = rawProviders.data.authProviders.sort(
      (prov1, prov2) => prov1.order - prov2.order
    );
    loading.value = false;
  } catch (e) {
    systemError.value = true;
    console.error('failed to fetch providers', e);
  }
});

function openProviderPopup(url, title, w, h) {
  var left = screen.width / 2 - w / 2;
  var top = screen.height / 2 - h / 2;
  return window.open(
    url,
    title,
    'menubar=yes,status=yes, replace=true, width=' +
      w +
      ', height=' +
      h +
      ', top=' +
      top +
      ', left=' +
      left
  );
}

function initiateOIDCLogin(providerID) {
  loading.value = true;
  providerPopup.value = openProviderPopup(
    `${import.meta.env.BASE_URL}provider?providerID=${providerID}`,
    '',
    700,
    770
  );
}
</script>

<template>
  <the-toast-notification
    v-if="systemError"
    :title="t('SignIn.errorToast.title')"
    :description="t('SignIn.errorToast.description')"
    type="error"
  />
  <div
    class="flex overflow-hidden flex-col justify-start items-center px-6 mx-6 w-full max-w-xl h-auto text-xl rounded-xl sm:w-screen md:text-3xl bg-gradient-dark"
  >
    <IconLogo class="py-12" />
    <div class="items-center mb-10 text-center md:mb-8">
      <span class="text-2xl font-bold md:text-4xl text-neutrals-white">
        {{ t('SignIn.heading') }}
      </span>
    </div>
    <div
      class="grid grid-cols-1 gap-5 justify-items-center content-center mb-12 w-full h-64 sm:px-32"
    >
      <IconSpinner v-if="loading" />
      <button
        v-for="(provider, index) in providers"
        v-else
        :id="provider.id"
        :key="index"
        class="flex flex-wrap items-center w-full h-11 text-sm font-bold rounded-md text-neutrals-dark bg-neutrals-softWhite"
        @click="initiateOIDCLogin(provider.id)"
        @keyup.enter="initiateOIDCLogin(provider.id)"
      >
        <img :src="provider.signInIconUrl[locale]" />
      </button>
    </div>
    <div class="mb-12 text-center">
      <p class="text-base font-normal text-neutrals-softWhite">
        {{ t('SignIn.redirect') }}
        <router-link
          class="whitespace-nowrap text-primary-blue underline-blue"
          :to="{ name: 'SignUp' }"
          >{{ t('SignIn.signup') }}
        </router-link>
      </p>
    </div>
  </div>
</template>
