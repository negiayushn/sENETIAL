import { CookiesCheck } from './checks/cookies';
import { DisclosureCheck } from './checks/disclosure';
import { ExposureCheck } from './checks/exposure';
import { HeadersCheck } from './checks/headers';
import { TlsCheck } from './checks/tls';
import type { Check } from './types';

/** Add a new check = write a class implementing `Check` and list it here. */
export const defaultChecks = (): Check[] => [new TlsCheck(), new HeadersCheck(), new CookiesCheck(), new DisclosureCheck(), new ExposureCheck()];
