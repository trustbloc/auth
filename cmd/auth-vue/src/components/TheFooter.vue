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
  <div class="py-8 w-full text-center px-15">
    <div class="hidden mx-auto text-center md:block text-neutrals-medium">
      © {{ date }} TrustBloc ･ {{ t('Footer.privacyPolicy') }} ･
      {{ t('Footer.terms') }} ･
      <TheLocaleSwitcher />
    </div>
    <div class="block md:hidden text-neutrals-medium">
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
