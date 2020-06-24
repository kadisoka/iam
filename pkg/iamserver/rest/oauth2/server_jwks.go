//

package oauth2

import (
	"github.com/emicklei/go-restful"
)

func (restSrv *Server) getJWKS(req *restful.Request, resp *restful.Response) {
	jwks := restSrv.jwtKeyChain().JWKSet()
	//TODO: caching directive
	resp.WriteJson(jwks, restful.MIME_JSON)
}
