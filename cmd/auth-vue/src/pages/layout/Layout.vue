/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

<template>
    <div class="wrapper">
        <layout-nav></layout-nav>
        <div class="contents">
            <transition name="fade" mode="out-in">
                <router-view></router-view>
            </transition>
            <layout-footer class="footer" v-if="!$route.meta.hideFooter"></layout-footer>
        </div>
    </div>
</template>

<script>
    import Footer from "./Footer.vue";
    import Nav from "./Nav.vue";
    export default {
        components: {
            LayoutFooter: Footer,
            LayoutNav: Nav
        }
    };
</script>

<style scoped>
    div {
        text-align: center;
    }
</style>
