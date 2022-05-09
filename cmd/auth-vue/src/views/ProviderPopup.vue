<script setup>
import { onMounted } from 'vue';
import IconSpinner from '@/components/icons/IconSpinner.vue';

const props = defineProps({
  providerID: {
    type: String,
    default: null,
  },
});

onMounted(() => {
  window.location.href = `/oidc/login?provider=${props.providerID}`;
});
</script>

<template>
  <div class="flex flex-col justify-center items-center">
    <IconSpinner />
    <span class="mt-8 text-base md:text-lg text-neutrals-dark"
      >Redirecting . . .</span
    >
  </div>
</template>
