/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import { nextTick } from 'vue';
import { createI18n } from 'vue-i18n';
import { setDocumentLang, setDocumentTitle } from '@/mixins/i18n/document';
import getStartingLocale from '@/mixins/i18n/getStartingLocale';

export function setupI18n() {
  const startingLocale = getStartingLocale();
  setDocumentLang(startingLocale.id);
  const i18n = createI18n({
    legacy: false,
    locale: startingLocale.id || 'en',
    fallbackLocale: startingLocale.id || 'en',
  });
  return i18n;
}

export async function loadI18nMessages(i18n, locale) {
  const messages = await import(
    /* webpackChunkName: "locale-[request]" */ `../translations/${locale}.json`
  );
  i18n.setLocaleMessage(locale, messages.default);
  return nextTick();
}

// This function updates i18n locale, loads new locale's messages and sets document properties accordingly
export async function updateI18nLocale(i18n, newLocale) {
  if (i18n?.availableLocales.length > 0 && i18n.locale === newLocale) {
    return nextTick();
  }

  // If the language was already loaded
  if (i18n.availableLocales.includes(newLocale)) {
    i18n.locale.value = newLocale;
    setDocumentLang(newLocale);
    setDocumentTitle(i18n.t('title'));
    return nextTick();
  }

  // If the language hasn't been loaded yet
  const messages = await import(
    /* webpackChunkName: "locale-[request]" */ `../translations/${newLocale}.json`
  );
  i18n.setLocaleMessage(newLocale, messages.default);
  setDocumentLang(newLocale);
  setDocumentTitle(i18n.t('title'));
  i18n.locale.value = newLocale;
  return nextTick();
}
