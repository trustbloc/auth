/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import TheRoot from './TheRoot.vue';
import supportedLocales from '@/config/supportedLocales';

// Lazy load the component
function load(name) {
  return () => import(`../views/${name}.vue`);
}

// Creates regex (en|fr)
function getLocaleRegex() {
  let reg = '';
  supportedLocales.forEach((locale, index) => {
    reg = `${reg}${locale.id}${
      index !== supportedLocales.length - 1 ? '|' : ''
    }`;
  });
  return `(${reg})`;
}

export default [
  {
    path: `/:locale${getLocaleRegex()}?`,
    component: TheRoot,
    redirect: 'sign-up',
    children: [
      {
        path: 'sign-in',
        name: 'SignIn',
        component: load('SignIn'),
        props: (route) => ({
          txnID: route.query.txnID,
        }),
      },
      {
        path: 'sign-up',
        name: 'SignUp',
        component: load('SignUp'),
        props: (route) => ({
          txnID: route.query.txnID,
        }),
      },
      {
        path: 'provider',
        name: 'ProviderPopup',
        component: load('ProviderPopup'),
        props: (route) => ({
          providerID: route.query.providerID,
          txnID: route.query.txnID,
        }),
      },
    ],
  },
  // will match everything and put it under `$route.params.pathMatch`
  {
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    component: load('NotFound'),
  },
];
