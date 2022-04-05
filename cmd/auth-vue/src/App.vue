<!--
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
-->

<script setup>
import { RouterView } from 'vue-router';
import TheFooter from '@/components/TheFooter.vue';
import { loadI18nMessages } from '@/plugins/i18n';
import { useI18n } from 'vue-i18n';
const i18n = useI18n();
// TODO: investigate why adding await prevents UI from rendering. Reference: https://vuejs.org/api/sfc-script-setup.html#top-level-await
loadI18nMessages(i18n, i18n.locale.value);
</script>

<template>
  <!-- <KeepAlive>
    <Suspense> -->
  <div
    class="flex flex-col justify-center items-center px-6 min-h-screen font-sans bg-scroll bg-neutrals-softWhite bg-no-repeat bg-onboarding-sm md:bg-onboarding"
  >
    <RouterView />
    <TheFooter class="absolute bottom-0" />
  </div>
  <!-- loading state -->
  <!-- <template #fallback> Loading... </template>
    </Suspense>
  </KeepAlive> -->
</template>
