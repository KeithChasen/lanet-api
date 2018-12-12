<?php

Route::group([
    'middleware' => ['cors']
], function ($router) {

    $router->post('register', ['as' => 'auth.register', 'uses' => 'AuthController@register']);
    $router->post('login', ['as' => 'auth.login', 'uses' => 'AuthController@login']);
    $router->post('me', ['as' => 'auth.me', 'uses' => 'AuthController@me']);

    $router->group(['middleware' => 'jwt.check'], function ($router) {
        $router->post('auth/refresh', ['as' => 'auth.refresh', 'uses' => 'AuthController@refresh']);
        $router->post('logout', ['as' => 'auth.logout', 'uses' => 'AuthController@logout']);
    });

    $router->group(['middleware' => 'jwt.auth'], function ($router) {
        $router->get('customers', 'CustomersController@index');
        $router->get('customers/{id}', 'CustomersController@show');
        $router->post('customers', 'CustomersController@store');
    });

});
