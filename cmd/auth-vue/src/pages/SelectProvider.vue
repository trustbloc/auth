<!--
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->

<template>
    <div class="container mx-auto flex  flex-wrap pt-4 pb-12">
        <div class="w-full md:w-1/3 p-6 flex flex-col flex-grow flex-shrink">
            <div class="flex-none mt-auto bg-white  rounded-b rounded-t-none overflow-hidden p-6">
                <div class="flex items-center justify-center">
                    <div class="bg-white shadow-lg border rounded text-center text-black px-32 pt-8 pb-8 md:flex-wrap md:justify-between">
                        <p class="text-xl">Select Sign-In Partner</p>
                        <div class="flex items-center  justify-center">
                            <a href="/oauth2/login?provider=github" class="mx-auto bg-gray-100 lg:mx-0 border hover:underline my-4 py-2 px-8 shadow-lg">
                                <img class="object-scale-down h-8 w-32"  alt="Google &quot;G&quot; Logo"
                                     src="https://upload.wikimedia.org/wikipedia/en/a/a4/Universal_Bank.svg"/>
                                Mock Bank
                            </a>
                        </div>
                        <div class="flex items-center justify-center">
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>
<script>
    export default {}
</script>


