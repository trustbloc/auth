<!--
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->

<template>
    <div class="container mx-auto flex  flex-wrap pt-4 pb-12">
        <div class="w-full md:w-1/3 p-6 flex flex-col flex-grow flex-shrink">
            <div class="flex-none mt-auto bg-white  rounded-b rounded-t-none overflow-hidden p-6">
                <div class="flex items-center justify-center">
                    <div class="bg-white shadow-lg border rounded text-left text-black px-10 pt-8 pb-8 md:flex-wrap md:justify-between">
                        <div class="grid grid-cols-3 gap-4">
                            <div class="grid grid-cols-1 col-span-2">
                                <p class="text-xl font-black pr-8">Select Sign-In Partner</p><br>
                                <p class="pr-8">By selecting a Sign-In Partner, you are agreeing to the Terms and Conditions and Privacy Notice of TrustBloc.</p>
                                <div class="grid grid-cols-3 flex items-center justify-center m-10" >
                                    <a class="mx-auto bg-gray-100 lg:mx-0 border hover:underline my-4 py-2 px-8
                                      shadow-lg text-center" v-for="(provider, index) in providers" :key="index"
                                       :href="'/oauth2/login?provider=' + provider.id">
                                        <img class="object-scale-down h-8 w-48"  alt="Google &quot;G&quot; Logo"
                                            :src="provider.logoURL"/>
                                        {{ provider.name }}
                                    </a>
                                </div>
                            </div>
                            <div>
                                <p class="text-xl font-medium pr-8">SIMPLE, CONVENIENT, SECURE</p><br>
                                <ul class="list-disc">
                                <li class="pr-8 mb-3">It's easy to use</li>
                                <li class="pr-8 mb-3">We protect your privacy</li>
                                <li class="pr-8 mb-3">No passwords or personal information (i.e.: name, address, date of birth, etc.) are exchanged during this process</li>
                                <li class="pr-8 mb-3">Your Sign-In Partner won't know which service you're accessing and the service won't know which Sign-In Partner you're using</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>
<script>

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
    }
</script>


