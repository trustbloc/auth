<!--
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
-->

<template>
  <div v-show="close" :class="classname">
    <div class="xs:flex-none px-4">
      <img class="w-8 h-6 sm:w-10 sm:h-8" :src="icon" />
    </div>
    <div class="flex-col">
      <span class="text-sm xs:text-lg font-bold leading-relaxed text-left">{{
        title
      }}</span>
      <div>
        <span class="text-xs xs:text-sm leading-6 text-left">{{
          description
        }}</span>
      </div>
    </div>
    <div class="xs:flex-none px-4 align-middle">
      <button type="button" @click="close = !close">
        <img class="w-6 h-6" src="@/assets/close-icon.svg" />
      </button>
    </div>
  </div>
</template>

<script>
export default {
  name: 'TheToastNotification',
  props: {
    title: {
      type: String,
      default: '',
    },
    description: {
      type: String,
      default: '',
    },
    type: {
      type: String,
      required: true,
    },
  },
  data() {
    return {
      classname: '',
      icon: '',
      close: true,
    };
  },
  created: function () {
    // Currently, only one type of toast message are supported i.e error, we can easily expand warning, success toast alerts as required etc.
    switch (this.type) {
      case 'error':
        this.classname = 'error-notification';
        this.icon = new URL(
          '../assets/triangle-exclamation.svg',
          import.meta.url
        ).href;
        break;
    }
  },
};
</script>
