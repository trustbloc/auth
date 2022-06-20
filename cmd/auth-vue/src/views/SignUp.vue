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

const props = defineProps({
  txnID: {
    type: String,
    default: null,
  },
});

onMounted(async () => {
  try {
    const rawProviders = await axios.get('/oidc/providers');
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
    `${import.meta.env.BASE_URL}provider?providerID=${providerID}&txnID=${
      props.txnID
    }`,
    '',
    700,
    770
  );
}
</script>

<template>
  <the-toast-notification
    v-if="systemError"
    :title="t('SignUp.errorToast.title')"
    :description="t('SignUp.errorToast.description')"
    type="error"
  />
  <div
    class="overflow-hidden h-auto text-xl rounded-xl md:max-w-4xl md:text-3xl bg-gradient-dark"
  >
    <div
      class="grid grid-cols-1 w-full h-full bg-no-repeat divide-x md:grid-cols-2 md:px-20 divide-neutrals-medium bg-onboarding-flare-lg divide-opacity-25"
    >
      <div class="hidden col-span-1 py-24 pr-16 md:block">
        <IconLogo class="mb-12" />
        <div class="flex overflow-y-auto flex-1 items-center mb-8 max-w-full">
          <img
            class="flex w-10 h-10"
            src="@/assets/signup/onboarding-icon-1.svg"
          />
          <span class="pl-5 text-base align-middle text-neutrals-white">
            {{ t('SignUp.leftContainer.span1') }}
          </span>
        </div>

        <div class="flex overflow-y-auto flex-1 items-center mb-8 max-w-full">
          <img
            class="flex w-10 h-10"
            src="@/assets/signup/onboarding-icon-2.svg"
          />
          <span class="pl-5 text-base align-middle text-neutrals-white">
            {{ t('SignUp.leftContainer.span2') }}
          </span>
        </div>

        <div class="flex overflow-y-auto flex-1 items-center max-w-full">
          <img
            class="flex w-10 h-10"
            src="@/assets/signup/onboarding-icon-3.svg"
          />
          <span class="pl-5 text-base align-middle text-neutrals-white">
            {{ t('SignUp.leftContainer.span3') }}
          </span>
        </div>
      </div>
      <div class="object-none object-center col-span-1 md:block">
        <div class="px-6 md:pt-16 md:pr-0 md:pb-12 md:pl-16">
          <IconLogo class="justify-center my-2 mt-12 md:hidden" />
          <div class="items-center pb-6 text-center">
            <h1 class="text-2xl font-bold md:text-4xl text-neutrals-white">
              {{ t('SignUp.heading') }}
            </h1>
          </div>
          <div
            class="grid grid-cols-1 gap-5 justify-items-center content-center mb-8 w-full h-64"
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
              <img :src="provider.signUpIconUrl[locale]" />
            </button>
          </div>
          <div class="mb-8 text-center">
            <p class="text-base font-normal text-neutrals-white">
              {{ t('SignUp.redirect') }}
              <router-link
                class="whitespace-nowrap text-primary-blue underline-blue"
                :to="{ name: 'SignIn' }"
                >{{ t('SignUp.signin') }}</router-link
              >
            </p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
