<!--
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->

<template>
  <div class="">
    <main>
      <div class="absolute w-full h-full gradient">
        <layout-nav></layout-nav>
        <div class="container mx-auto px-4 h-full">
          <div class="flex content-center items-center justify-center h-full">
            <div class="w-full lg:w-5/12">
              <div class="relative flex flex-col min-w-0 break-words w-full mb-6 shadow-lg rounded-lg bg-gray-200 border-0">
                <div class="rounded-t mb-0 px-6 py-6">
                </div>
                <div class="flex-auto px-4 lg:px-10 py-10 pt-0">
                  <label class="block text-black text-lg font-semibold mb-2">Choose Sign In Provider</label>
                  <hr class="mt-4 border-b-1 border-gray-400" />
                  <div class="grid grid-cols-1 col-span-2">
                    <div class="grid grid-cols-3 flex items-center justify-center m-4" >
                      <a class="mx-auto w-full bg-gray-100 lg:mx-0 border hover:underline my-4 py-2 px-2
                                      shadow-lg text-center" v-for="(provider, index) in providers" :key="index"
                         :href="'/oauth2/login?provider=' + provider.id">
                        <img class="object-scale-down h-8 w-48"  alt="Google &quot;G&quot; Logo"
                             :src="provider.logoURL"/>
                        {{ provider.name }}
                      </a>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <layout-footer class="footer" v-if="!$route.meta.hideFooter"></layout-footer>
    </main>
  </div>
</template>

<script>
import Footer from "./layout/Footer.vue";
import Nav from "./layout/Nav.vue";
import axios from 'axios';

export default  {
  name: "selectProvider",
  data () {
    return {
      providers:[]
    }
  },
  mounted() {
    axios
        .get('/oauth2/providers')
        .then(response => {
          this.providers = response.data.authProviders
        })
  },
  components: {
    LayoutFooter: Footer,
    LayoutNav: Nav
  }
}
</script>
<style>
.gradient {
  background: linear-gradient(to right ,#13113F, #261131,  #1A0C22,  #261131, #14061D);
}
</style>
