/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

<template>
    <div class="w-full container mx-auto flex flex-wrap items-center justify-between mt-0 py-2">
        <div class="pl-4 flex items-center">
            <a class="toggleColour text-black no-underline hover:no-underline font-bold text-2xl lg:text-4xl"  href="javascript:history.back()">
                <i class="fa fa-cubes" style="font-size:32px;color:black"></i>
                TrustBloc Sign-In
            </a>
        </div>
        <div class="w-full flex-grow lg:flex lg:items-center lg:w-auto hidden lg:block mt-2 lg:mt-0 bg-white lg:bg-transparent text-black p-4 lg:p-0 z-20">
            <ul class="list-reset lg:flex justify-end flex-1 items-center">
                <li class="mr-3">
                    <a class="inline-block text-black no-underline hover:text-green hover:text-underline py-2 px-4" href="">About Us</a>
                </li>
                <li class="mr-3">
                    <a class="inline-block text-black no-underline hover:text-green hover:text-underline py-2 px-4" href="https://github.com/trustbloc/hub-auth">Github</a>
                </li>
            </ul>
        </div>
    </div>
</template>

<script>
    export default {
        name: "Nav.vue"
    }
</script>
