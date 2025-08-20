rule DifferentCityLogin {
  meta:

  events:
    $udm.metadata.event_type = "USER_LOGIN"
    $udm.principal.user.userid = $user
    $udm.principal.location.city = $city

  match:
    $user over 5m

  condition:
    $udm and #city > 1
}
