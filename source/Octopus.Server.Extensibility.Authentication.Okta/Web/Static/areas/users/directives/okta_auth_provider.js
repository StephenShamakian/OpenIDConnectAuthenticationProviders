var module = angular.module('octopusApp.users.okta');

module.directive("oktaAuthProvider", function () {
    return {
        restrict: 'E',
        replace: true,
        transclude: true,
        controller: 'OktaAuthController',
        scope: {
            provider: '=',
            isSubmitting: '=',
            handleSignInError: '=',
            shouldAutoLogin: '='
        },
        template: '<a ng-click="signIn()"><div class="external-provider-button okta-button"><img src="{{ \'~/images/okta/aura_solid_blue.png\' | resolveLink }}"/><div>Sign in with Okta</div></div></a>'
    };
});
