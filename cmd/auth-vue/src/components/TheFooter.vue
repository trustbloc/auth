<!--
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
-->

<script setup>
import TheLocaleSwitcher from '@/components/TheLocaleSwitcher.vue';
import { useI18n } from 'vue-i18n';
const { t } = useI18n();
</script>

<template>
  <div class="py-8 px-15 w-full text-center">
    <div class="hidden mx-auto text-center text-neutrals-medium md:block">
      © {{ date }} TrustBloc ･ {{ t('Footer.privacyPolicy') }} ･
      {{ t('Footer.terms') }} ･
      <TheLocaleSwitcher />
    </div>
    <div class="block text-neutrals-medium md:hidden">
      <ul class="list-inside">
        <li>
          <span class="whitespace-nowrap">{{ t('Footer.privacyPolicy') }}</span>
          ･
          <span class="whitespace-nowrap">{{ t('Footer.terms') }}</span>
        </li>
        <li>
          <span class="whitespace-nowrap">© {{ date }} TrustBloc</span> ･
          <TheLocaleSwitcher />
        </li>
      </ul>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      date: new Date().getFullYear(),
    };
  },
};
</script>
