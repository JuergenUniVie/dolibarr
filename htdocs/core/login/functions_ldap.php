<?php
/* Copyright (C) 2007-2011 Laurent Destailleur  <eldy@users.sourceforge.net>
 * Copyright (C) 2008-2021 Regis Houssin        <regis.houssin@inodbox.com>
 * Copyright (C) 2024      MDW                  <mdeweerd@users.noreply.github.com>
 * Copyright (C) 2024      William Mead         <william.mead@manchenumerique.fr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 */

/**
 *       \file       htdocs/core/login/functions_ldap.php
 *       \ingroup    core
 *       \brief      Authentication functions for LDAP
 */


/**
 * Check validity of user/password/entity
 * If test is ko, reason must be filled into $_SESSION["dol_loginmesg"]
 *
 * @param   string  $usertotest     Login
 * @param   string  $passwordtotest Password
 * @param   int     $entitytotest   Numero of instance (always 1 if module multicompany not enabled)
 * @return  string          Login if OK, '' if KO
 */
function check_user_password_ldap($usertotest, $passwordtotest, $entitytotest)
{
    global $db, $conf, $langs;
    global $dolibarr_main_auth_ldap_host, $dolibarr_main_auth_ldap_port;
    global $dolibarr_main_auth_ldap_version, $dolibarr_main_auth_ldap_servertype;
    global $dolibarr_main_auth_ldap_login_attribute, $dolibarr_main_auth_ldap_dn;
    global $dolibarr_main_auth_ldap_admin_login, $dolibarr_main_auth_ldap_admin_pass;
    global $dolibarr_main_auth_ldap_filter;
    global $dolibarr_main_auth_ldap_debug;

    // Force master entity in transversal mode
    $entity = $entitytotest;
    if (isModEnabled('multicompany') && getDolGlobalString('MULTICOMPANY_TRANSVERSE_MODE')) {
        $entity = 1;
    }

    $login = '';
    $resultFetchUser = '';

    if (!function_exists("ldap_connect")) {
        dol_syslog("functions_ldap::check_user_password_ldap Authentication KO failed to connect to LDAP. LDAP functions are disabled on this PHP", LOG_ERR);
        sleep(1);

        // Load translation files required by the page
        $langs->loadLangs(array('main', 'other'));

        $_SESSION["dol_loginmesg"] = $langs->transnoentitiesnoconv("ErrorLDAPFunctionsAreDisabledOnThisPHP").' '.$langs->transnoentitiesnoconv("TryAnotherConnectionMode");
        return '';
    }

    if ($usertotest) {
        dol_syslog("functions_ldap::check_user_password_ldap usertotest=".$usertotest." passwordtotest=".preg_replace('/./', '*', $passwordtotest)." entitytotest=".$entitytotest);

        $ldaphost = $dolibarr_main_auth_ldap_host;
        $ldapport = $dolibarr_main_auth_ldap_port;
        $ldapversion = $dolibarr_main_auth_ldap_version;
        $ldapservertype = (empty($dolibarr_main_auth_ldap_servertype) ? 'openldap' : $dolibarr_main_auth_ldap_servertype);

        $ldapuserattr = $dolibarr_main_auth_ldap_login_attribute;
        $ldapdn = $dolibarr_main_auth_ldap_dn;
        $ldapadminlogin = $dolibarr_main_auth_ldap_admin_login;
        $ldapadminpass = $dolibarr_main_auth_ldap_admin_pass;
        $ldapdebug = ((empty($dolibarr_main_auth_ldap_debug) || $dolibarr_main_auth_ldap_debug == "false") ? false : true);

        if ($ldapdebug) {
            print "DEBUG: Logging LDAP steps<br>\n";
        }

        require_once DOL_DOCUMENT_ROOT.'/core/class/ldap.class.php';
        $ldap = new Ldap();
        $ldap->server = explode(',', $ldaphost);
        $ldap->serverPort = $ldapport;
        $ldap->ldapProtocolVersion = $ldapversion;
        $ldap->serverType = $ldapservertype;
        $ldap->searchUser = $ldapadminlogin;
        $ldap->searchPassword = $ldapadminpass;

        if ($ldapdebug) {
            dol_syslog("functions_ldap::check_user_password_ldap Server:".implode(',', $ldap->server).", Port:".$ldap->serverPort.", Protocol:".$ldap->ldapProtocolVersion.", Type:".$ldap->serverType);
            dol_syslog("functions_ldap::check_user_password_ldap uid/samaccountname=".$ldapuserattr.", dn=".$ldapdn.", Admin:".$ldap->searchUser.", Pass:".dol_trunc($ldap->searchPassword, 3));
            print "DEBUG: Server:".implode(',', $ldap->server).", Port:".$ldap->serverPort.", Protocol:".$ldap->ldapProtocolVersion.", Type:".$ldap->serverType."<br>\n";
            print "DEBUG: uid/samaccountname=".$ldapuserattr.", dn=".$ldapdn.", Admin:".$ldap->searchUser.", Pass:".dol_trunc($ldap->searchPassword, 3)."<br>\n";
        }

        // First step: Connect with admin account and find user's DN
        $resultFetchLdapUser = 0;

        // Define search filter
        $userSearchFilter = "(&(objectClass=Person)(".$ldapuserattr."=".$usertotest."))";

        $result = $ldap->connectBind();
        if ($result > 0) {
            $resultFetchLdapUser = $ldap->fetch($usertotest, $userSearchFilter);
            if ($resultFetchLdapUser <= 0) {
                dol_syslog("functions_ldap::check_user_password_ldap User not found in LDAP");
                if ($ldapdebug) {
                    print "DEBUG: User not found in LDAP<br>\n";
                }
                $ldap->unbind();
                sleep(1);
                $_SESSION["dol_loginmesg"] = $langs->transnoentitiesnoconv("ErrorBadLoginPassword");
                return '';
            }

            // Check if password needs to be changed
            if ($resultFetchLdapUser > 0 && $ldap->pwdlastset == 0) {
                dol_syslog('functions_ldap::check_user_password_ldap '.$usertotest.' must change password next logon');
                if ($ldapdebug) {
                    print "DEBUG: User ".$usertotest." must change password<br>\n";
                }
                $ldap->unbind();
                sleep(1);
                $langs->load('ldap');
                $_SESSION["dol_loginmesg"] = $langs->transnoentitiesnoconv("YouMustChangePassNextLogon", $usertotest, $ldap->domainFQDN);
                return '';
            }
            $ldap->unbind();
        }

        // Second step: Try to bind with user's DN and password
        if ($resultFetchLdapUser > 0 && !empty($ldap->ldapUserDN)) {
            $ldap->searchUser = $ldap->ldapUserDN;
            $ldap->searchPassword = $passwordtotest;

            if ($ldapdebug) {
                dol_syslog("functions_ldap::check_user_password_ldap Trying to bind with DN: ".$ldap->searchUser);
                print "DEBUG: Trying to bind with DN: ".$ldap->searchUser."<br>\n";
            }

            $result = $ldap->connectBind();
            if ($result > 0) {
                if ($result == 2) {  // Connection is ok for user/pass into LDAP
                    $login = $usertotest;
                    dol_syslog("functions_ldap::check_user_password_ldap $login authentication ok");

                    if (getDolGlobalString('LDAP_FIELD_LOGIN') && !empty($ldap->login)) {
                        $login = $ldap->login;
                        dol_syslog("functions_ldap::check_user_password_ldap login is now $login");
                    }

                    // LDAP to Dolibarr synchronization
                    if ($login && !empty($conf->ldap->enabled) && getDolGlobalInt('LDAP_SYNCHRO_ACTIVE') == Ldap::SYNCHRO_LDAP_TO_DOLIBARR) {
                        dol_syslog("functions_ldap::check_user_password_ldap Sync ldap2dolibarr");

                        // Get SID for Active Directory
                        $sid = null;
                        if (getDolGlobalString('LDAP_SERVER_TYPE') == "activedirectory") {
                            $sid = $ldap->getObjectSid($login);
                        }

                        // Try to find user in Dolibarr
                        $usertmp = new User($db);
                        $resultFetchUser = $usertmp->fetch('', $login, $sid, 1, ($entitytotest > 0 ? $entitytotest : -1));

                        if ($resultFetchUser > 0) {
                            // Update login if it changed
                            if ($usertmp->login != $ldap->login && $ldap->login) {
                                $usertmp->login = $ldap->login;
                                $usertmp->update($usertmp);
                            }
                        }

                        unset($usertmp);
                    }

                    // Check multicompany access if needed
                    if (isModEnabled('multicompany')) {
                        global $mc;
                        $usertmp = new User($db);
                        $usertmp->fetch('', $login);

                        if (is_object($mc)) {
                            $ret = $mc->checkRight($usertmp->id, $entitytotest);
                            if ($ret < 0) {
                                dol_syslog("functions_ldap::check_user_password_ldap Authentication KO entity '".$entitytotest."' not allowed for user id '".$usertmp->id."'", LOG_NOTICE);
                                $login = '';
                            }
                        }
                        unset($usertmp);
                    }
                }
            } else {
                dol_syslog("functions_ldap::check_user_password_ldap Authentication failed for '$usertotest'", LOG_NOTICE);
                sleep(1);
                $_SESSION["dol_loginmesg"] = $langs->transnoentitiesnoconv("ErrorBadLoginPassword");
            }
        }

        $ldap->unbind();
    }

    return $login;
}

	return $login;
}
