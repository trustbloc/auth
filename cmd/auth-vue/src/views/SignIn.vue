<!--
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
-->

<script setup>
import TheToastNotification from '@/components/TheToastNotification.vue';
import IconLogo from '@/components/icons/IconLogo.vue';
import IconSpinner from '@/components/icons/IconSpinner.vue';
import useBreakpoints from '@/plugins/breakpoints.js';
import { useI18n } from 'vue-i18n';

const { t } = useI18n();
</script>

<template>
  <the-toast-notification
    v-if="systemError"
    :title="t('SignIn.errorToast.title')"
    :description="t('SignIn.errorToast.description')"
    type="error"
  />
  <div
    class="flex overflow-hidden flex-col justify-start items-center px-6 mx-6 w-full max-w-xl h-auto text-xl bg-gradient-dark rounded-xl sm:w-screen md:text-3xl"
  >
    <IconLogo class="py-12" />
    <div class="items-center mb-10 text-center md:mb-8">
      <span class="text-2xl font-bold text-neutrals-white md:text-4xl">
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
        :key="index"
        class="flex flex-wrap items-center w-full h-11 text-sm font-bold text-neutrals-dark bg-neutrals-softWhite rounded-md"
        @click="beginOIDCLogin(provider.id)"
        @keyup.enter="beginOIDCLogin(provider.id)"
      >
        <img :id="provider.id" :src="provider.signInLogoUrl" />
      </button>
    </div>
    <div class="mb-12 text-center">
      <p class="text-base font-normal text-neutrals-softWhite">
        {{ t('SignIn.redirect') }}
        <router-link
          class="text-primary-blue whitespace-nowrap underline-blue"
          :to="{ name: 'SignUp' }"
          >{{ t('SignIn.signup') }}
        </router-link>
      </p>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      providers: [],
      statusMsg: '',
      loading: true,
      systemError: false,
      breakpoints: useBreakpoints(),
    };
  },
};
</script>
