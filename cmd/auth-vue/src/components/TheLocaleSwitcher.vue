<!--
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
-->

<script setup>
import { computed } from 'vue';
import supportedLocales from '@/config/supportedLocales';
import { updateI18nLocale } from '@/plugins/i18n';
import { useI18n } from 'vue-i18n';
import { useRouter, useRoute } from 'vue-router';

const i18n = useI18n();
const router = useRouter();
const route = useRoute();
const newLocale = computed(() =>
  i18n.locale.value === 'en'
    ? supportedLocales.find((loc) => loc.id === 'fr')
    : supportedLocales.find((loc) => loc.id === 'en')
);
const handleLocaleSwitch = async (newLocale) => {
  if (i18n.locale !== newLocale.id) {
    await updateI18nLocale(i18n, newLocale.id);
    router.replace({
      name: route.name.value,
      params: {
        ...route.params.value,
        locale: newLocale.base,
      },
    });
  }
};
</script>

<template>
  <a
    tabindex="0"
    class="cursor-pointer"
    @click="handleLocaleSwitch(newLocale)"
    @keyup.enter="handleLocaleSwitch(newLocale)"
  >
    {{ newLocale.name }}
  </a>
</template>
