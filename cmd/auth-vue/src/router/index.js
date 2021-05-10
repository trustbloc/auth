/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import SelectProvider from '@/pages/SelectProvider'
import NotFound from '@/pages/PageNotFound'

const routes = [
    {
        path: "/ui",
        component: SelectProvider,
        name: "main",
        redirect: "ui/selectProvider",
        children: [
            {
                path: "selectProvider",
                name: "selectProvider",
                component: SelectProvider
            }
        ]
    },
    {
        path: '*',
        name: 'NotFound',
        component: NotFound
    }
];

export default routes;
