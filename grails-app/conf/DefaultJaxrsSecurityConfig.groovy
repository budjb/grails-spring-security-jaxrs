security {
    apiKey {
        header = 'X-Authentication-ApiKey'
        query = 'apikey'
    }
    authTypes = ['HEADER', 'QUERY']
    rejectIfNoRule = true
    enabled = true
}
