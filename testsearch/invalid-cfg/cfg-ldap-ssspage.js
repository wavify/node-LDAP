{
    "uri":            "ldap://testldap.internal.net",
    "binddn":         "cn=manager,dc=test",
    "password":       "secret",
    "validatecert":    false,
    "connecttimeout":  -1,
    "base":            "dc=test",
    "attrs":           "*",
    "filter":          "(objectClass=*)",
    "sortString": "entryDN:caseIgnoreOrderingMatch",
    "searchRequestControlType": "pagedresults",
    "pagesize": 50
}
