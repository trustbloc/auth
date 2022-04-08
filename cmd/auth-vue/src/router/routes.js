/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Lazy load the component
function load(name) {
  return () => import(`../views/${name}.vue`);
}

export default [
  {
    path: '/sign-in',
    name: 'SignIn',
    component: load('SignIn'),
  },
  {
    path: '/sign-up',
    name: 'SignUp',
    component: load('SignUp'),
  },
  // will match everything and put it under `$route.params.pathMatch`
  {
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    component: load('NotFound'),
  },
];
