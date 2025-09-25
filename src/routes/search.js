const db = require('../services/arango');

// postSearch takes a json array of PuRLs and returns a list of vulnerabilities
async function postSearch(request, reply){
    
}


async function routes(fastify, options) {
    fastify.post('/', postSearch);
}
module.exports = routes;