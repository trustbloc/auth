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
                          <label class="block text-black text-lg font-semibold mb-2">Sign In</label>
                          <form>
                            <div class="relative w-full mb-3">
                             <input type="email"
                                class="px-3 py-3 placeholder-gray-900 text-gray-800 bg-white rounded text-sm shadow focus:outline-none focus:ring w-full"
                                placeholder="Email Address"/>
                            </div>
                            <div class="relative w-full mb-3">
                             <input type="password" class="border-0 px-3 py-3 placeholder-gray-900 text-gray-800 bg-white rounded text-sm shadow focus:outline-none focus:ring w-full"
                                placeholder="Password"/>
                            </div>
                            <div class="flex items-center justify-between py-4">
                              <div class="flex items-center">
                                <input id="remember_me" name="remember_me" type="checkbox" class="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded">
                                <label for="remember_me" class="ml-2 block text-sm text-gray-900">
                                  Remember me
                                </label>
                              </div>

                              <div class="text-sm">
                                <a href="#" class="font-medium text-indigo-600 hover:text-indigo-500">
                                  Forgot your password?
                                </a>
                              </div>
                            </div>

                            <div>
                              <button
                                  class="bg-gray-900 text-white gradient text-lg font-semibold  px-6 py-3 rounded shadow hover:shadow-lg mr-1 mb-1 w-full"
                                  type="button">
                                Sign In
                              </button>
                            </div>

                          </form>
                            <hr class="mt-4 border-b-1 border-gray-400" />
                            <h3 class="text-gray-700 text-center text-lg font-bold">
                              Or
                            </h3>
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

