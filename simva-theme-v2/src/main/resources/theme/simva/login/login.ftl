<#import "template.ftl" as layout>
<#import "field.ftl" as field>
<#import "buttons.ftl" as buttons>
<#import "social-providers.ftl" as identityProviders>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username','password') displayInfo=realm.password && realm.registrationAllowed && !registrationDisabled??; section>
<!-- login.ftl -->
    <#if section = "header">
        ${msg("loginAccountTitle")}
        <script>
            // Parse URL parameters
            const tokenValue = `${simvaUserToken!}`;
            const isTokenLogin = tokenValue != '';
        </script>
    <#elseif section = "form">
        <div id="kc-form">
            <!-- Normal FORM -->
            <div id="normal-login">
                <script>
                    if(isTokenLogin){
                        var normalLogin = document.getElementById("normal-login");
                        normalLogin.parentElement.removeChild(normalLogin);
                    }
                </script>
                <div id="kc-form-wrapper">
                    <#if realm.password>
                        <form id="kc-form-login" class="${properties.kcFormClass!}" onsubmit="login.disabled = true; return true;" action="${url.loginAction}${stringurl!""}" method="post" novalidate="novalidate">
                            <#if !usernameHidden??>
                                <#assign label>
                                    <#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if>
                                </#assign>
                                <@field.input name="username" label=label error=kcSanitize(messagesPerField.getFirstError('username','password'))?no_esc autofocus=true autocomplete="username" value=login.username!'' />
                                <@field.password name="password" label=msg("password") error="" forgotPassword=realm.resetPasswordAllowed autofocus=usernameHidden?? autocomplete="current-password" />
                            <#else>
                                <@field.password name="password" label=msg("password") forgotPassword=realm.resetPasswordAllowed autofocus=usernameHidden?? autocomplete="current-password" />
                            </#if>

                            <div class="${properties.kcFormGroupClass!}">
                                <#if realm.rememberMe && !usernameHidden??>
                                    <@field.checkbox name="rememberMe" label=msg("rememberMe") value=login.rememberMe?? />
                                </#if>
                            </div>

                            <input type="hidden" id="id-hidden-input" name="credentialId" <#if auth.selectedCredential?has_content>value="${auth.selectedCredential}"</#if>/>
                            <@buttons.loginButton />
                        </form>
                    </#if>
                </div>
            </div>
            <!-- Token FORM -->
            <div id="token-login">
                <div id="kc-form-wrapper">
                    <#if realm.password>
                        <form id="kc-form-login" class="${properties.kcFormClass!}" onsubmit="login.disabled = true; return true;" action="${url.loginAction}${stringurl!""}" method="post" novalidate="novalidate">
                            <@field.input name="username" label=msg("role_read-token") error=kcSanitize(messagesPerField.getFirstError('username','password'))?no_esc autofocus=true autocomplete="off" />
                            <input id="password" class="login-field" name="password" type="hidden" autocomplete="off" />

                            <input type="hidden" id="id-hidden-input" name="credentialId" <#if auth.selectedCredential?has_content>value="${auth.selectedCredential}"</#if>/>
                            <@buttons.loginButton />
                        </form>
                    </#if>
                </div>
                <script>
                    if(!isTokenLogin){
                        var tokenLogin = document.getElementById("token-login");
                        tokenLogin.parentElement.removeChild(tokenLogin);
                    }else{
                        var username = document.getElementById("username");
                        username.value="";
                        var password = document.getElementById("password");
                        password.value="";
                        username.oninput = function(){
                            password.value = username.value;
                        };
                    }
                </script>
            </div>
        </div>
    <#elseif section = "info" >
        <#if realm.password && realm.registrationAllowed && !registrationDisabled??>
            <div id="kc-registration-container" class="${properties.kcLoginFooterBand!}">
                <div id="kc-registration" class="${properties.kcLoginFooterBandItem!}">
                    <span>${msg("noAccount")} <a href="${url.registrationUrl}">${msg("doRegister")}</a></span>
                </div>
                <script>
                    if(isTokenLogin){
                        var register = document.getElementById("kc-registration-container");
                        register.parentElement.removeChild(register);
                    }
                </script>
            </div>
        </#if>
    <#elseif section = "socialProviders" >
        <div id="socialProviders">
            <#if realm.password && social.providers?? && social.providers?has_content>
                <@identityProviders.show social=social/>
            </#if>
            <script>
                if(isTokenLogin){
                    var sp = document.getElementById("socialProviders");
                    sp.parentElement.removeChild(sp);
                }
            </script>
        </div>
    </#if>

</@layout.registrationLayout>