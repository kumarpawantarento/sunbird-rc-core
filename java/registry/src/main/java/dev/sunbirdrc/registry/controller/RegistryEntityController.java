package dev.sunbirdrc.registry.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.sunbirdrc.keycloak.OwnerCreationException;
import dev.sunbirdrc.pojos.AsyncRequest;
import dev.sunbirdrc.pojos.PluginResponseMessage;
import dev.sunbirdrc.pojos.Response;
import dev.sunbirdrc.pojos.ResponseParams;
import dev.sunbirdrc.registry.digilocker.pulldoc.PullDocRequest;
import dev.sunbirdrc.registry.digilocker.pulldoc.PullDocResponse;
import dev.sunbirdrc.registry.digilocker.pulluriresponse.Person;
import dev.sunbirdrc.registry.digilocker.pulluriresponse.PullURIResponse;
import dev.sunbirdrc.registry.entities.AttestationPolicy;
import dev.sunbirdrc.registry.exception.AttestationNotFoundException;
import dev.sunbirdrc.registry.exception.ErrorMessages;
import dev.sunbirdrc.registry.exception.RecordNotFoundException;
import dev.sunbirdrc.registry.exception.UnAuthorizedException;
import dev.sunbirdrc.registry.middleware.MiddlewareHaltException;
import dev.sunbirdrc.registry.middleware.util.Constants;
import dev.sunbirdrc.registry.middleware.util.JSONUtil;
import dev.sunbirdrc.registry.middleware.util.OSSystemFields;
import dev.sunbirdrc.registry.service.FileStorageService;
import dev.sunbirdrc.registry.service.impl.CertificateServiceImpl;
import dev.sunbirdrc.registry.transform.Configuration;
import dev.sunbirdrc.registry.transform.Data;
import dev.sunbirdrc.registry.transform.ITransformer;
import org.agrona.Strings;
import dev.sunbirdrc.registry.util.DigiLockerUtils;
import dev.sunbirdrc.registry.util.DocDetails;
import dev.sunbirdrc.registry.util.ViewTemplateManager;
import dev.sunbirdrc.validators.ValidationException;
import org.apache.commons.lang3.StringUtils;
import org.apache.tinkerpop.gremlin.structure.Vertex;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

import static dev.sunbirdrc.registry.Constants.*;
import static dev.sunbirdrc.registry.middleware.util.Constants.ENTITY_TYPE;

@RestController
public class RegistryEntityController extends AbstractController {

    private static final String TRANSACTION_ID = "transactionId";
    private static Logger logger = LoggerFactory.getLogger(RegistryEntityController.class);
    @Value("${GCS_SERVICE_URL:https://casa.upsmfac.org/UploadedFiles/Student/}")
    public static final String GCS_SERVICE_URL = "http://34.100.212.156:8082/";
    @Value("${digilocker_hmackey:}")
    public static final String DIGILOCKER_KEY = "vTV3Jl81kXDOca70TT2+P/YAb5DXnS+DDr/ArlFhow0=";
    @Autowired
    private CertificateServiceImpl certificateService;

    @Autowired
    private FileStorageService fileStorageService;

    @Autowired
    private AsyncRequest asyncRequest;

    @Autowired
    private ViewTemplateManager viewTemplateManager;

    @Value("${authentication.enabled:true}")
    boolean securityEnabled;
    @Value("${certificate.enableExternalTemplates:false}")
    boolean externalTemplatesEnabled;

    @RequestMapping(value = "/api/v1/{entityName}/invite", method = RequestMethod.POST)
    public ResponseEntity<Object> invite(
            @PathVariable String entityName,
            @RequestHeader HttpHeaders header,
            @RequestBody JsonNode rootNode,
            HttpServletRequest request
    ) {
        final String TAG = "RegistryController:invite";
        logger.info("Inviting entity {}", rootNode);
        ResponseParams responseParams = new ResponseParams();
        Response response = new Response(Response.API_ID.INVITE, "OK", responseParams);
        Map<String, Object> result = new HashMap<>();
        ObjectNode newRootNode = objectMapper.createObjectNode();
        newRootNode.set(entityName, rootNode);
        try {
            checkEntityNameInDefinitionManager(entityName);
            registryHelper.authorizeInviteEntity(request, entityName);
            watch.start(TAG);
            String entityId = registryHelper.inviteEntity(newRootNode, "");
            registryHelper.autoRaiseClaim(entityName, entityId, "", null, newRootNode, dev.sunbirdrc.registry.Constants.USER_ANONYMOUS);
            Map resultMap = new HashMap();
            resultMap.put(dbConnectionInfoMgr.getUuidPropertyName(), entityId);
            result.put(entityName, resultMap);
            response.setResult(result);
            responseParams.setStatus(Response.Status.SUCCESSFUL);
            watch.start(TAG);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (RecordNotFoundException e) {
            createSchemaNotFoundResponse(e.getMessage(), responseParams);
            response = new Response(Response.API_ID.INVITE, "ERROR", responseParams);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        } catch (MiddlewareHaltException | ValidationException | OwnerCreationException e) {
            return badRequestException(responseParams, response, e.getMessage());
        } catch (UnAuthorizedException unAuthorizedException) {
            return createUnauthorizedExceptionResponse(unAuthorizedException);
        } catch (Exception e) {
            if (e.getCause() != null && e.getCause().getCause() != null &&
                    e.getCause().getCause() instanceof InvocationTargetException) {
                Throwable targetException = ((InvocationTargetException) (e.getCause().getCause())).getTargetException();
                if (targetException instanceof OwnerCreationException) {
                    return badRequestException(responseParams, response, targetException.getMessage());
                }
            }
            return internalErrorResponse(responseParams, response, e);
        }
    }

    @NotNull
    private void createSchemaNotFoundResponse(String errorMessage, ResponseParams responseParams) {
        responseParams.setStatus(Response.Status.UNSUCCESSFUL);
        responseParams.setErrmsg(errorMessage);
    }

    private void checkEntityNameInDefinitionManager(String entityName) throws RecordNotFoundException {
        if (definitionsManager.getDefinition(entityName) == null) {
            String errorMessage = String.format(ErrorMessages.NOT_PART_OF_THE_SYSTEM_EXCEPTION, entityName);
            throw new RecordNotFoundException(errorMessage);
        }
    }

    @RequestMapping(value = "/api/v1/{entityName}/{entityId}", method = RequestMethod.DELETE)
    public ResponseEntity<Object> deleteEntity(
            @PathVariable String entityName,
            @PathVariable String entityId,
            @RequestHeader HttpHeaders header,
            HttpServletRequest request
    ) {

        String userId = USER_ANONYMOUS;
        logger.info("Deleting entityType {} with Id {}", entityName, entityId);
        if (registryHelper.doesEntityOperationRequireAuthorization(entityName)) {
            try {

                userId = registryHelper.authorize(entityName, entityId, request);
            } catch (Exception e) {
                return createUnauthorizedExceptionResponse(e);
            }
        }
        ResponseParams responseParams = new ResponseParams();
        Response response = new Response(Response.API_ID.DELETE, "OK", responseParams);
        try {
            checkEntityNameInDefinitionManager(entityName);
            String tag = "RegistryController.delete " + entityName;
            watch.start(tag);
            Vertex deletedEntity = registryHelper.deleteEntity(entityName, entityId, userId);
            if (deletedEntity != null && deletedEntity.keys().contains(OSSystemFields._osSignedData.name())) {
                registryHelper.revokeExistingCredentials(entityName, entityId, userId, deletedEntity.value(OSSystemFields._osSignedData.name()));
            }
            responseParams.setErrmsg("");
            responseParams.setStatus(Response.Status.SUCCESSFUL);
            watch.stop(tag);
            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (RecordNotFoundException e) {
            createSchemaNotFoundResponse(e.getMessage(), responseParams);
            response = new Response(Response.API_ID.DELETE, "ERROR", responseParams);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            logger.error("RegistryController: Exception while Deleting entity", e);
            responseParams.setStatus(Response.Status.UNSUCCESSFUL);
            responseParams.setErrmsg(e.getMessage());
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);

        }
    }

    @RequestMapping(value = "/api/v1/{entityName}/search", method = RequestMethod.POST)
    public ResponseEntity<Object> searchEntity(@PathVariable String entityName, @RequestHeader HttpHeaders header, @RequestBody ObjectNode searchNode) {

        ResponseParams responseParams = new ResponseParams();
        Response response = new Response(Response.API_ID.SEARCH, "OK", responseParams);

        try {
            watch.start("RegistryController.searchEntity");
            ArrayNode entity = JsonNodeFactory.instance.arrayNode();
            entity.add(entityName);
            searchNode.set(ENTITY_TYPE, entity);
            checkEntityNameInDefinitionManager(entityName);
            if (definitionsManager.getDefinition(entityName).getOsSchemaConfiguration().getEnableSearch()) {
                JsonNode result = registryHelper.searchEntity(searchNode);
                watch.stop("RegistryController.searchEntity");
                return new ResponseEntity<>(result.get(entityName), HttpStatus.OK);
            } else {
                watch.stop("RegistryController.searchEntity");
                logger.error("Searching on entity {} not allowed", entityName);
                response.setResult("");
                responseParams.setStatus(Response.Status.UNSUCCESSFUL);
                responseParams.setErrmsg(String.format("Searching on entity %s not allowed", entityName));
            }
        } catch (RecordNotFoundException e) {
            createSchemaNotFoundResponse(e.getMessage(), responseParams);
            response = new Response(Response.API_ID.SEARCH, "ERROR", responseParams);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            logger.error("Exception in controller while searching entities !", e);
            response.setResult("");
            responseParams.setStatus(Response.Status.UNSUCCESSFUL);
            responseParams.setErrmsg(e.getMessage());
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @RequestMapping(value = "/api/v1/{entityName}/{entityId}", method = RequestMethod.PUT)
    public ResponseEntity<Object> putEntity(
            @PathVariable String entityName,
            @PathVariable String entityId,
            @RequestBody JsonNode rootNode,
            HttpServletRequest request) {

        logger.info("Updating entityType {} request body {}", entityName, rootNode);
        String userId = USER_ANONYMOUS;
        if (registryHelper.doesEntityOperationRequireAuthorization(entityName)) {
            try {

                userId = registryHelper.authorize(entityName, entityId, request);
            } catch (Exception e) {
                return createUnauthorizedExceptionResponse(e);
            }
        }
        ResponseParams responseParams = new ResponseParams();
        Response response = new Response(Response.API_ID.UPDATE, "OK", responseParams);
        ((ObjectNode) rootNode).put(uuidPropertyName, entityId);
        ObjectNode newRootNode = objectMapper.createObjectNode();
        newRootNode.set(entityName, rootNode);

        try {
            checkEntityNameInDefinitionManager(entityName);
            String tag = "RegistryController.update " + entityName;
            watch.start(tag);
            JsonNode existingNode = registryHelper.readEntity(newRootNode, userId);
            String emailId = registryHelper.fetchEmailIdFromToken(request, entityName);
            registryHelper.updateEntityAndState(existingNode, newRootNode, userId);
            if (existingNode.get(entityName).has(OSSystemFields._osSignedData.name())) {
                registryHelper.revokeExistingCredentials(entityName, entityId, userId,
                        existingNode.get(entityName).get(OSSystemFields._osSignedData.name()).asText(""));
            }
            registryHelper.invalidateAttestation(entityName, entityId, userId, null);
            registryHelper.autoRaiseClaim(entityName, entityId, userId, existingNode, newRootNode, emailId);
            responseParams.setErrmsg("");
            responseParams.setStatus(Response.Status.SUCCESSFUL);
            watch.stop(tag);

            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (RecordNotFoundException e) {
             createSchemaNotFoundResponse(e.getMessage(), responseParams);
            response = new Response(Response.API_ID.PUT, "ERROR", responseParams);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            logger.error("RegistryController: Exception while updating entity (without id)!", e);
            responseParams.setStatus(Response.Status.UNSUCCESSFUL);
            responseParams.setErrmsg(e.getMessage());
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @RequestMapping(value = "/api/v1/{entityName}", method = RequestMethod.POST)
    public ResponseEntity<Object> postEntity(
            @PathVariable String entityName,
            @RequestHeader HttpHeaders header,
            @RequestBody JsonNode rootNode,
            @RequestParam(defaultValue = "sync") String mode,
            @RequestParam(defaultValue = "${webhook.url}") String callbackUrl,
            HttpServletRequest request
    ) {

        logger.info("MODE: {}", asyncRequest.isEnabled());
        logger.info("MODE: {}", asyncRequest.getWebhookUrl());
        logger.info("Adding entity {}", rootNode);
        ResponseParams responseParams = new ResponseParams();
        Response response = new Response(Response.API_ID.POST, "OK", responseParams);
        Map<String, Object> result = new HashMap<>();
        ObjectNode newRootNode = objectMapper.createObjectNode();
        newRootNode.set(entityName, rootNode);

        try {
            checkEntityNameInDefinitionManager(entityName);
            String userId = registryHelper.authorizeManageEntity(request, entityName);
            String label = registryHelper.addEntity(newRootNode, userId);
            String emailId = registryHelper.fetchEmailIdFromToken(request, entityName);
            Map<String, String> resultMap = new HashMap<>();
            if (asyncRequest.isEnabled()) {
                resultMap.put(TRANSACTION_ID, label);
            } else {
                registryHelper.autoRaiseClaim(entityName, label, userId, null, newRootNode, emailId);
                resultMap.put(dbConnectionInfoMgr.getUuidPropertyName(), label);
            }
            result.put(entityName, resultMap);
            response.setResult(result);
            responseParams.setStatus(Response.Status.SUCCESSFUL);
            watch.stop("RegistryController.addToExistingEntity");

            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (RecordNotFoundException e) {
             createSchemaNotFoundResponse(e.getMessage(), responseParams);
            response = new Response(Response.API_ID.POST, "ERROR", responseParams);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        } catch (MiddlewareHaltException e) {
            logger.info("Error in validating the request");
            return badRequestException(responseParams, response, e.getMessage());
        } catch (Exception e) {
            logger.error("Exception in controller while adding entity !", e);
            response.setResult(result);
            responseParams.setStatus(Response.Status.UNSUCCESSFUL);
            responseParams.setErrmsg(e.getMessage());
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @RequestMapping(value = "/api/v1/{entityName}/{entityId}/**", method = RequestMethod.PUT)
    public ResponseEntity<Object> updatePropertyOfTheEntity(
            HttpServletRequest request,
            @PathVariable String entityName,
            @PathVariable String entityId,
            @RequestBody JsonNode requestBody

    ) {
        String userId = USER_ANONYMOUS;
        if (registryHelper.doesEntityOperationRequireAuthorization(entityName)) {
            try {
                userId = registryHelper.authorize(entityName, entityId, request);
            } catch (Exception e) {
                return createUnauthorizedExceptionResponse(e);
            }
        }
        ResponseParams responseParams = new ResponseParams();
        Response response = new Response(Response.API_ID.UPDATE, "OK", responseParams);

        try {
            checkEntityNameInDefinitionManager(entityName);
            String tag = "RegistryController.update " + entityName;
            watch.start(tag);
            requestBody = registryHelper.removeFormatAttr(requestBody);
            JsonNode existingNode = registryHelper.readEntity(userId, entityName, entityId, false, null, false);
            registryHelper.updateEntityProperty(entityName, entityId, requestBody, request, existingNode);
            if (existingNode.get(entityName).has(OSSystemFields._osSignedData.name())) {
                registryHelper.revokeExistingCredentials(entityName, entityId, userId,
                        existingNode.get(entityName).get(OSSystemFields._osSignedData.name()).asText(""));
            }
            responseParams.setErrmsg("");
            responseParams.setStatus(Response.Status.SUCCESSFUL);
            registryHelper.invalidateAttestation(entityName, entityId, userId, registryHelper.getPropertyToUpdate(request, entityId));
            watch.stop(tag);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (RecordNotFoundException e) {
             createSchemaNotFoundResponse(e.getMessage(), responseParams);
            response = new Response(Response.API_ID.PUT, "ERROR", responseParams);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            responseParams.setErrmsg(e.getMessage());
            responseParams.setStatus(Response.Status.UNSUCCESSFUL);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        }
    }

    @RequestMapping(value = "/api/v1/{entityName}/{entityId}/**", method = RequestMethod.POST)
    public ResponseEntity<Object> addNewPropertyToTheEntity(
            HttpServletRequest request,
            @PathVariable String entityName,
            @PathVariable String entityId,
            @RequestHeader HttpHeaders header,
            @RequestBody JsonNode requestBody
    ) {
        ResponseParams responseParams = new ResponseParams();
        Response response = new Response(Response.API_ID.UPDATE, "OK", responseParams);
        try {
            checkEntityNameInDefinitionManager(entityName);
            registryHelper.authorize(entityName, entityId, request);
        } catch (RecordNotFoundException e) {
           createSchemaNotFoundResponse(e.getMessage(), responseParams);
           response = new Response(Response.API_ID.POST, "ERROR", responseParams);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            return createUnauthorizedExceptionResponse(e);
        }

        try {

            String tag = "RegistryController.addNewPropertyToTheEntity " + entityName;
            watch.start(tag);
            String notes = getNotes(requestBody);
            requestBody = registryHelper.removeFormatAttr(requestBody);
            registryHelper.addEntityProperty(entityName, entityId, requestBody, request);
            responseParams.setErrmsg("");
            responseParams.setStatus(Response.Status.SUCCESSFUL);
            watch.stop(tag);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            responseParams.setErrmsg(e.getMessage());
            responseParams.setStatus(Response.Status.UNSUCCESSFUL);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        }
    }

    private String getNotes(JsonNode requestBody) {
        String notes = "";
        if (requestBody.has("notes")) {
            notes = requestBody.get("notes").asText();
            JSONUtil.removeNodes(requestBody, Collections.singletonList("notes"));
        }
        return notes;
    }

    private JsonNode getAttestationSignedData(String attestationId, JsonNode node) throws AttestationNotFoundException, JsonProcessingException {
        JsonNode attestationNode = getAttestationNode(attestationId, node);
        if (attestationNode.get(OSSystemFields._osAttestedData.name()) == null)
            throw new AttestationNotFoundException();
        attestationNode = objectMapper.readTree(attestationNode.get(OSSystemFields._osAttestedData.name()).asText());
        return attestationNode;
    }

    @Nullable
    private JsonNode getAttestationNode(String attestationId, JsonNode node) {
        Iterator<JsonNode> iterator = node.iterator();
        JsonNode attestationNode = null;
        while (iterator.hasNext()) {
            attestationNode = iterator.next();
            if (attestationNode.get(uuidPropertyName).toString().equals(attestationId)) {
                break;
            }
        }
        return attestationNode;
    }

    @RequestMapping(value = "/partner/api/v1/{entityName}", method = RequestMethod.GET)
    public ResponseEntity<Object> getEntityWithConsent(
            @PathVariable String entityName,
            HttpServletRequest request) {
        ResponseParams responseParams = new ResponseParams();
        try {
            checkEntityNameInDefinitionManager(entityName);
            ArrayList<String> fields = getConsentFields(request);
            JsonNode userInfoFromRegistry = registryHelper.getRequestedUserDetails(request, entityName);
            JsonNode jsonNode = userInfoFromRegistry.get(entityName);
            if (jsonNode instanceof ArrayNode) {
                ArrayNode values = (ArrayNode) jsonNode;
                if (values.size() > 0) {
                    JsonNode node = values.get(0);
                    if (node instanceof ObjectNode) {
                        ObjectNode entityNode = copyWhiteListedFields(fields, node);
                        return new ResponseEntity<>(entityNode, HttpStatus.OK);
                    }
                }
            }
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        } catch (RecordNotFoundException e) {
             createSchemaNotFoundResponse(e.getMessage(), responseParams);
           Response response = new Response(Response.API_ID.GET, "ERROR", responseParams);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            logger.error("Error in partner api access", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @RequestMapping(value = "/api/v2/{entityName}", method = RequestMethod.GET)
    public ResponseEntity<Object> getUserDetails(
            @PathVariable String entityName,
            HttpServletRequest request) {
        ResponseParams responseParams = new ResponseParams();
        try {
            checkEntityNameInDefinitionManager(entityName);
            ArrayList<String> fields = getConsentFields(request);
            JsonNode userInfoFromRegistry = registryHelper.getRequestedUserDetailsSearch(request, entityName);
            JsonNode jsonNode = userInfoFromRegistry.get(entityName);
            if (jsonNode instanceof ArrayNode) {
                ArrayNode values = (ArrayNode) jsonNode;
                if (values.size() > 0) {
                    JsonNode node = values.get(0);
                    if (node instanceof ObjectNode) {
                        ObjectNode entityNode = copyWhiteListedFields(fields, node);
                        return new ResponseEntity<>(entityNode, HttpStatus.OK);
                    }
                }
            }
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        } catch (RecordNotFoundException e) {
            createSchemaNotFoundResponse(e.getMessage(), responseParams);
            Response response = new Response(Response.API_ID.GET, "ERROR", responseParams);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            logger.error("Error in partner api access", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private ObjectNode copyWhiteListedFields(ArrayList<String> fields, JsonNode dataNode) {
        ObjectNode node = JsonNodeFactory.instance.objectNode();
        for (String key : fields) {
            node.set(key, dataNode.get(key));
        }
        return node;
    }

    private ArrayList<String> getConsentFields(HttpServletRequest request) {
        ArrayList<String> fields = new ArrayList<>();
        KeycloakAuthenticationToken principal = (KeycloakAuthenticationToken) request.getUserPrincipal();
        try {
            Map<String, Object> otherClaims = ((KeycloakPrincipal) principal.getPrincipal()).getKeycloakSecurityContext().getToken().getOtherClaims();
            if (otherClaims.keySet().contains(dev.sunbirdrc.registry.Constants.KEY_CONSENT) && otherClaims.get(dev.sunbirdrc.registry.Constants.KEY_CONSENT) instanceof Map) {
                Map consentFields = (Map) otherClaims.get(dev.sunbirdrc.registry.Constants.KEY_CONSENT);
                for (Object key : consentFields.keySet()) {
                    fields.add(key.toString());
                }
            }
        } catch (Exception ex) {
            logger.error("Error while extracting other claims", ex);
        }
        return fields;
    }

    @RequestMapping(value = "/api/v1/{entityName}/{entityId}", method = RequestMethod.GET, produces =
            {MediaType.APPLICATION_PDF_VALUE, MediaType.TEXT_HTML_VALUE, Constants.SVG_MEDIA_TYPE})
    public ResponseEntity<Object> getEntityType(@PathVariable String entityName,
                                                @PathVariable String entityId,
                                                HttpServletRequest request,
                                                @RequestHeader(required = false) String viewTemplateId) {
        ResponseParams responseParams = new ResponseParams();
        Response response ;
        if (registryHelper.doesEntityOperationRequireAuthorization(entityName) && securityEnabled) {
            try {

                registryHelper.authorize(entityName, entityId, request);
            } catch (Exception e) {
                try {
                    checkEntityNameInDefinitionManager(entityName);
                    registryHelper.authorizeAttestor(entityName, request);
                } catch (RecordNotFoundException re) {
                         createSchemaNotFoundResponse(re.getMessage(), responseParams);
                        response = new Response(Response.API_ID.GET, "ERROR", responseParams);
                        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
                } catch (Exception exceptionFromAuthorizeAttestor) {
                    return new ResponseEntity<>(HttpStatus.FORBIDDEN);
                }
            }
        }
        try {
            String readerUserId = getUserId(entityName, request);
            JsonNode node = registryHelper.readEntity(readerUserId, entityName, entityId, false,
                            viewTemplateManager.getViewTemplateById(viewTemplateId), false)
                    .get(entityName);
            JsonNode signedNode = objectMapper.readTree(node.get(OSSystemFields._osSignedData.name()).asText());

            String templateUrlFromRequest = getTemplateUrlFromRequest(request, entityName);

            return new ResponseEntity<>(certificateService.getCertificate(signedNode,
                    entityName,
                    entityId,
                    request.getHeader(HttpHeaders.ACCEPT),
                    templateUrlFromRequest,
                    JSONUtil.removeNodesByPath(node, definitionsManager.getExcludingFieldsForEntity(entityName))
            ), HttpStatus.OK);
        } catch (Exception exception) {
            exception.printStackTrace();
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }


    private String getTemplateUrlFromRequest(HttpServletRequest request, String entityName) {
        String template = Template;

        if(entityName.equalsIgnoreCase("StudentForeignVerification")){
            return "StudentForeignVerificationTemp";
        } else if (entityName.equalsIgnoreCase("StudentGoodstanding")) {
            return "StudentGoodStandingTemp";
        }

        if (externalTemplatesEnabled && !StringUtils.isEmpty(request.getHeader(template))) {
            return request.getHeader(template);
        }
        if (definitionsManager.getCertificateTemplates(entityName) != null && definitionsManager.getCertificateTemplates(entityName).size() > 0 && !StringUtils.isEmpty(request.getHeader(TemplateKey))) {
            String templateUri = definitionsManager.getCertificateTemplates(entityName).getOrDefault(request.getHeader(TemplateKey), null);
            if (!StringUtils.isEmpty(templateUri)) {
                try {
                    if (templateUri.startsWith(MINIO_URI_PREFIX)) {
                        return fileStorageService.getSignedUrl(templateUri.substring(MINIO_URI_PREFIX.length()));
                    } else if (templateUri.startsWith(HTTP_URI_PREFIX) || templateUri.startsWith(HTTPS_URI_PREFIX)) {
                        return templateUri;
                    }
                } catch (Exception e) {
                    logger.error("Exception while parsing certificate templates DID urls", e);
                    return null;
                }
            }

        }
        return null;
    }

    private String getTemplateUrlFromRequestFromRegType(HttpServletRequest request, String entityName) {
        if (externalTemplatesEnabled && !StringUtils.isEmpty(request.getHeader(Template))) {
            return request.getHeader(Template);
        }
        if (definitionsManager.getCertificateTemplates(entityName) != null && definitionsManager.getCertificateTemplates(entityName).size() > 0 && !StringUtils.isEmpty(request.getHeader(TemplateKey))) {
            String templateUri = definitionsManager.getCertificateTemplates(entityName).getOrDefault(request.getHeader(TemplateKey), null);
            if (!StringUtils.isEmpty(templateUri)) {
                try {
                    if (templateUri.startsWith(MINIO_URI_PREFIX)) {
                        return fileStorageService.getSignedUrl(templateUri.substring(MINIO_URI_PREFIX.length()));
                    } else if (templateUri.startsWith(HTTP_URI_PREFIX) || templateUri.startsWith(HTTPS_URI_PREFIX)) {
                        return templateUri;
                    }
                } catch (Exception e) {
                    logger.error("Exception while parsing certificate templates DID urls", e);
                    return null;
                }
            }

        }
        return null;
    }

    @RequestMapping(value = "/api/v1/{entityName}/{entityId}", method = RequestMethod.GET)
    public ResponseEntity<Object> getEntity(
            @PathVariable String entityName,
            @PathVariable String entityId,
            @RequestHeader HttpHeaders header, HttpServletRequest request,
            @RequestHeader(required = false) String viewTemplateId) {
        boolean requireLDResponse = false;
        boolean requireVCResponse = false;
        for (MediaType t : header.getAccept()) {
            if (t.toString().equals(Constants.LD_JSON_MEDIA_TYPE)) {
                requireLDResponse = true;
                break;
            } else if (t.toString().equals(Constants.VC_JSON_MEDIA_TYPE)) {
                requireVCResponse = true;
            }
        }
        if (registryHelper.doesEntityOperationRequireAuthorization(entityName) && securityEnabled) {
            try {
                registryHelper.authorize(entityName, entityId, request);
            } catch (Exception e) {
                try {
                    registryHelper.authorizeAttestor(entityName, request);
                } catch (Exception exceptionFromAuthorizeAttestor) {
                    return new ResponseEntity<>(HttpStatus.FORBIDDEN);
                }
            }
        }
        ResponseParams responseParams = new ResponseParams();
        Response response = new Response(Response.API_ID.READ, "OK", responseParams);
        try {
            checkEntityNameInDefinitionManager(entityName);
            String readerUserId = getUserId(entityName, request);
            JsonNode node = getEntityJsonNode(entityName, entityId, requireLDResponse, readerUserId, viewTemplateId);
            if (requireLDResponse) {
                addJsonLDSpec(node);
            } else if (requireVCResponse) {
                String vcString = node.get(OSSystemFields._osSignedData.name()).textValue();
                return new ResponseEntity<>(vcString, HttpStatus.OK);
            }
            return new ResponseEntity<>(node, HttpStatus.OK);

        } catch (RecordNotFoundException re) {
             createSchemaNotFoundResponse(re.getMessage(), responseParams);
            response = new Response(Response.API_ID.GET, "ERROR", responseParams);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            logger.error("Read Api Exception occurred ", e);
            responseParams.setErrmsg(e.getMessage());
            responseParams.setStatus(Response.Status.UNSUCCESSFUL);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private String getUserId(String entityName, HttpServletRequest request) throws Exception {
        return registryHelper.getUserId(request, entityName);
    }

    private void addJsonLDSpec(JsonNode node) {

    }

    private JsonNode getEntityJsonNode(@PathVariable String entityName, @PathVariable String entityId,
                                       boolean requireLDResponse, String userId, String viewTemplateId) throws Exception {
        JsonNode resultNode = registryHelper.readEntity(userId, entityName, entityId, false,
                viewTemplateManager.getViewTemplateById(viewTemplateId), false);
        Data<Object> data = new Data<>(resultNode);
        Configuration config = configurationHelper.getResponseConfiguration(requireLDResponse);
        ITransformer<Object> responseTransformer = transformer.getInstance(config);
        Data<Object> resultContent = responseTransformer.transform(data);
        logger.info("ReadEntity,{},{}", entityId, resultContent);
        if (!(resultContent.getData() instanceof JsonNode)) {
            throw new RuntimeException("Unknown response object " + resultContent);
        }
        JsonNode node = (JsonNode) resultContent.getData();
        JsonNode entityNode = node.get(entityName);
        return entityNode != null ? entityNode : node;
    }

    @RequestMapping(value = "/api/v1/{entityName}", method = RequestMethod.GET)
    public ResponseEntity<Object> getEntityByToken(@PathVariable String entityName, HttpServletRequest request,
                                                   @RequestHeader(required = false) String viewTemplateId) throws RecordNotFoundException {
        ResponseParams responseParams = new ResponseParams();
        Response response = new Response(Response.API_ID.GET, "OK", responseParams);
        try {
            checkEntityNameInDefinitionManager(entityName);
            String userId = registryHelper.getUserId(request, entityName);
            if (!Strings.isEmpty(userId)) {
                JsonNode responseFromDb = registryHelper.searchEntitiesByUserId(entityName, userId, viewTemplateId);
                JsonNode entities = responseFromDb.get(entityName);
                if (entities.size() > 0) {
                    return new ResponseEntity<>(entities, HttpStatus.OK);
                } else {
                    responseParams.setErrmsg("No record found");
                    responseParams.setStatus(Response.Status.UNSUCCESSFUL);
                    return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
                }
            } else {
                responseParams.setErrmsg("User id is empty");
                responseParams.setStatus(Response.Status.UNSUCCESSFUL);
                return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
            }
        } catch (RecordNotFoundException e) {
             createSchemaNotFoundResponse(e.getMessage(),responseParams);
            response = new Response(Response.API_ID.GET, "ERROR", responseParams);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            logger.error("Exception in controller while searching entities !", e);
            response.setResult("");
            responseParams.setStatus(Response.Status.UNSUCCESSFUL);
            responseParams.setErrmsg(e.getMessage());
            return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
        }
    }

    //TODO: check the usage and deprecate the api if not used
    @GetMapping(value = "/api/v1/{entity}/{entityId}/attestationProperties")
    public ResponseEntity<Object> getEntityForAttestation(
            @PathVariable String entity,
            @PathVariable String entityId
    ) {
         ResponseParams responseParams = new ResponseParams();
        try {
            JsonNode resultNode = registryHelper.readEntity("", entity, entityId, false, null, false);
            ObjectNode objectNode = objectMapper.createObjectNode();
            objectNode.set("entity", resultNode.get(entity));
            checkEntityNameInDefinitionManager(entity);
            List<AttestationPolicy> attestationPolicies = definitionsManager.getDefinition(entity)
                    .getOsSchemaConfiguration()
                    .getAttestationPolicies();
            objectNode.set("attestationPolicies", objectMapper.convertValue(attestationPolicies, JsonNode.class));
            return new ResponseEntity<>(objectNode, HttpStatus.OK);

        } catch (RecordNotFoundException re) {
             createSchemaNotFoundResponse(re.getMessage(), responseParams);
            Response response = new Response(Response.API_ID.GET, "ERROR", responseParams);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        }
        catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    //TODO: check the usage and deprecate the api if not used
    @RequestMapping(value = "/api/v1/{entityName}/{entityId}", method = RequestMethod.PATCH)
    public ResponseEntity<Object> attestEntity(
            @PathVariable String entityName,
            @PathVariable String entityId,
            @RequestHeader HttpHeaders header,
            @RequestBody JsonNode rootNode
    ) throws Exception {
        ResponseParams responseParams = new ResponseParams();
        try {
            checkEntityNameInDefinitionManager(entityName);
        } catch (RecordNotFoundException re) {
             createSchemaNotFoundResponse(re.getMessage(),responseParams);
            Response response = new Response(Response.API_ID.PATCH, "ERROR", responseParams);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        }

        logger.info("Attestation request for {}", rootNode.get("fieldPaths"));
        JsonNode nodePath = rootNode.get("jsonPaths");
        if (nodePath instanceof ArrayNode) {
            Iterator<JsonNode> elements = ((ArrayNode) nodePath).elements();
            ArrayList<String> paths = new ArrayList<>();
            for (Iterator<JsonNode> it = elements; it.hasNext(); ) {
                JsonNode e = it.next();
                paths.add(e.textValue());
            }
            JsonNode node = registryHelper.readEntity("admin", entityName, entityId, false, null, false);
            registryHelper.attestEntity(entityName, node, paths.toArray(new String[]{}), "admin");
        }
        return null;
    }

    //TODO: check the usage and deprecate the api if not used
    @RequestMapping(value = "/api/v1/system/{property}/{propertyId}", method = RequestMethod.POST)
    public ResponseEntity<ResponseParams> updateProperty(
            @PathVariable String property,
            @PathVariable String propertyId,
            @RequestBody JsonNode requestBody) {
        logger.info("Got system request for the property {} {}", property, propertyId);
        ((ObjectNode) requestBody).put(uuidPropertyName, propertyId);
        ObjectNode newRootNode = objectMapper.createObjectNode();

        ResponseParams responseParams = new ResponseParams();
        newRootNode.set(property, requestBody);
        try {
            String response = registryHelper.updateProperty(newRootNode, "");
            responseParams.setStatus(Response.Status.SUCCESSFUL);
            responseParams.setResultList(Collections.singletonList(response));
            return new ResponseEntity<>(responseParams, HttpStatus.OK);
        } catch (Exception exception) {
            responseParams.setStatus(Response.Status.UNSUCCESSFUL);
            responseParams.setErrmsg(exception.getMessage());
            exception.printStackTrace();
            return new ResponseEntity<>(responseParams, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    //TODO: API called by claim-ms, need to be blocked from external access
    @RequestMapping(value = "/api/v1/{property}/{propertyId}/attestation/{attestationName}/{attestationId}", method = RequestMethod.PUT)
    public ResponseEntity<ResponseParams> updateAttestationProperty(
            @PathVariable String property,
            @PathVariable String propertyId,
            @PathVariable String attestationName,
            @PathVariable String attestationId,
            @RequestBody JsonNode requestBody) {
        logger.info("Got system request to update attestation property {} {} {} {}", property, propertyId, attestationName, attestationId);
        ((ObjectNode) requestBody).put(uuidPropertyName, propertyId);
        ObjectNode newRootNode = objectMapper.createObjectNode();

        ResponseParams responseParams = new ResponseParams();
        newRootNode.set(property, requestBody);
        try {
            logger.info("updateAttestationProperty: {}", requestBody);
            PluginResponseMessage pluginResponseMessage = objectMapper.convertValue(requestBody, PluginResponseMessage.class);
            registryHelper.updateState(pluginResponseMessage);
            responseParams.setStatus(Response.Status.SUCCESSFUL);
            responseParams.setResultList(Collections.singletonList("response"));
            return new ResponseEntity<>(responseParams, HttpStatus.OK);
        } catch (Exception exception) {
            responseParams.setStatus(Response.Status.UNSUCCESSFUL);
            responseParams.setErrmsg(exception.getMessage());
            exception.printStackTrace();
            return new ResponseEntity<>(responseParams, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Deprecated
    @RequestMapping(value = "/api/v1/{entityName}/sign", method = RequestMethod.GET)
    public ResponseEntity<Object> getSignedEntityByToken(@PathVariable String entityName, HttpServletRequest request) {
        ResponseParams responseParams = new ResponseParams();
        Response response = new Response(Response.API_ID.SEARCH, "OK", responseParams);
        try {
            checkEntityNameInDefinitionManager(entityName);
            JsonNode result = registryHelper.getRequestedUserDetails(request, entityName);
            if (result.get(entityName).size() > 0) {
                Object credentialTemplate = definitionsManager.getCredentialTemplate(entityName);
                Object signedCredentials = registryHelper.getSignedDoc(result.get(entityName).get(0), credentialTemplate);
                return new ResponseEntity<>(signedCredentials, HttpStatus.OK);
            } else {
                responseParams.setErrmsg("Entity not found");
                responseParams.setStatus(Response.Status.UNSUCCESSFUL);
                return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
            }
        } catch (RecordNotFoundException re) {
             createSchemaNotFoundResponse(re.getMessage(), responseParams);
            response = new Response(Response.API_ID.GET, "ERROR", responseParams);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            logger.error("Exception in controller while searching entities !", e);
            response.setResult("");
            responseParams.setStatus(Response.Status.UNSUCCESSFUL);
            responseParams.setErrmsg(e.getMessage());
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping(value = "/api/v1/{entityName}/{entityId}/attestation/{attestationName}/{attestationId}",
            produces = {MediaType.APPLICATION_PDF_VALUE, MediaType.TEXT_HTML_VALUE, Constants.SVG_MEDIA_TYPE, MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<Object> getAttestationCertificate(HttpServletRequest request, @PathVariable String entityName, @PathVariable String entityId,
                                                            @PathVariable String attestationName, @PathVariable String attestationId) {
        ResponseParams responseParams = new ResponseParams();
        try {
            checkEntityNameInDefinitionManager(entityName);
            String readerUserId = getUserId(entityName, request);
            JsonNode node = registryHelper.readEntity(readerUserId, entityName, entityId, false, null, false)
                    .get(entityName).get(attestationName);
            JsonNode attestationNode = getAttestationSignedData(attestationId, node);
            return new ResponseEntity<>(certificateService.getCertificate(attestationNode,
                    entityName,
                    entityId,
                    request.getHeader(HttpHeaders.ACCEPT),
                    getTemplateUrlFromRequest(request, entityName),
                    getAttestationNode(attestationId, node)
            ), HttpStatus.OK);

        } catch (RecordNotFoundException re) {
            createSchemaNotFoundResponse(re.getMessage(), responseParams);
            Response response = new Response(Response.API_ID.GET, "ERROR", responseParams);
            try {
                return new ResponseEntity<>(objectMapper.writeValueAsString(response), HttpStatus.NOT_FOUND);
            } catch (JsonProcessingException e) {
                return new ResponseEntity<>(HttpStatus.NOT_FOUND);
            }
        } catch (AttestationNotFoundException e) {
            logger.error(e.getMessage());
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }
    @RequestMapping(value = "/api/v1/{entityName}/{entityId}/revoke", method = RequestMethod.POST)
    public ResponseEntity<Object> revokeACredential (
            HttpServletRequest request,
            @PathVariable String entityName,
            @PathVariable String entityId,
            @RequestHeader HttpHeaders headers
    ){
        String userId = USER_ANONYMOUS;
        logger.info("Revoking the entityType {} with {} Id",entityName, entityId);
        // Check fot Authorisation
        if (registryHelper.doesEntityOperationRequireAuthorization(entityName)) {
            try {
                userId = registryHelper.authorize(entityName, entityId, request);
            } catch (Exception e) {
                return createUnauthorizedExceptionResponse(e);
            }
        }
        ResponseParams responseParams = new ResponseParams();
        Response response = new Response(Response.API_ID.REVOKE, "OK", responseParams);
        try {
            String tag = "RegistryController.revokeAnExistingCredential " + entityName;
            watch.start(tag);
            JsonNode existingEntityNode = getEntityJsonNode(entityName, entityId,false, userId, null);
            String signedData = existingEntityNode.get(OSSystemFields._osSignedData.name()).asText();
            if (signedData.equals(new String()) || signedData.equals(null)) {
                throw new RecordNotFoundException("Credential is already revoked");
            }
            JsonNode revokedEntity = registryHelper.revokeAnEntity( entityName ,entityId, userId, existingEntityNode);
            if (revokedEntity != null) {
                registryHelper.revokeExistingCredentials(entityName, entityId, userId, signedData);
            }
            responseParams.setErrmsg("");
            responseParams.setStatus(Response.Status.SUCCESSFUL);
            watch.stop(tag);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            logger.error("Registry Controller: Exception while revoking an entity:", e);
            responseParams.setStatus(Response.Status.UNSUCCESSFUL);
            responseParams.setErrmsg(e.getMessage());
            return new ResponseEntity<>(response,HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * PULL-URI-Request API for DigiLocker
     * @param request
     * @param entityName
     * @return
     */
    @RequestMapping(value = "/api/v1/pullUriRequest/{entityName}", method = RequestMethod.POST, produces =
            {MediaType.APPLICATION_XML_VALUE}, consumes = {MediaType.APPLICATION_XML_VALUE,MediaType.APPLICATION_PDF_VALUE, MediaType.TEXT_HTML_VALUE, Constants.SVG_MEDIA_TYPE})
    public ResponseEntity<Object> issueCertificateToDigiLocker(HttpServletRequest request, @PathVariable String entityName) {

        //String entityName = "RegCertificate"; - take entity name from input - TODO
        // call template TODO
        String templateurl = null;
        String statusCode = "1";
        Scanner scanner = null;
        try {
            scanner = new Scanner(request.getInputStream(), "UTF-8");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        String xmlString = null;
        if(scanner!=null){
            Scanner scanner1 = scanner.useDelimiter("\\A");
            if(scanner1.hasNext())
                xmlString =  scanner1.next();
        }
        DocDetails docDetails = null;
        // Map to JAXB
        xmlString = DigiLockerUtils.getXmlString(xmlString);
        //request.set
        ResponseParams responseParams = new ResponseParams();
        Response response = new Response(Response.API_ID.SEARCH, "OK", responseParams);
        String osid = null;
        JsonNode result = null;
        try {
            result = registryHelper.getRequestedUserDetailsCustom(request, entityName, xmlString);
            if (result != null && result.get(entityName) != null && result.get(entityName).size() > 0) {
                ArrayNode responseFromDb = registryHelper.fetchFromDBUsingEsResponse(entityName, (ArrayNode) result.get(entityName));
                if(responseFromDb!=null && responseFromDb.size() > 0){
                    osid = responseFromDb.get(0).get("osid").asText();
                }
            }
        } catch (Exception e) {
            statusCode = "0";
            e.printStackTrace();
            return new ResponseEntity<>(statusCode, HttpStatus.INTERNAL_SERVER_ERROR);
        }

        if(osid!=null) {
            try {
                String readerUserId = getUserId(entityName, request);
                JsonNode node = registryHelper.readEntity(readerUserId, entityName, osid, false, null, false)
                        .get(entityName);
                String fileName = DigiLockerUtils.getDocUri();
                Object certificate = null;
                JsonNode signedNode = objectMapper.readTree(node.get(OSSystemFields._osSignedData.name()).asText());
                certificate = certificateService.getCred(fileName + ".PDF");

                if(certificate == null){
                    certificate = certificateService.getCertificateForDGL(signedNode,
                            entityName,
                            osid,
                            MediaType.APPLICATION_PDF_VALUE,
                            getTemplateUrlFromRequest(request, entityName),
                            JSONUtil.removeNodesByPath(node, definitionsManager.getExcludingFieldsForEntity(entityName)), fileName
                    );

                    certificateService.saveToGCS(certificate, fileName);
                }
                Person person = DigiLockerUtils.getPersonDetail(result, entityName);
                PullURIResponse pullResponse = DigiLockerUtils.getPullUriResponse(fileName, statusCode, osid, certificate, person);
                String responseString = DigiLockerUtils.convertJaxbToString(pullResponse);
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_XML);
                return new ResponseEntity<>(responseString, headers, HttpStatus.OK);
            } catch (Exception exception) {
                statusCode = "0";
                exception.printStackTrace();
                return new ResponseEntity<>(statusCode, HttpStatus.BAD_REQUEST);
            }
        }
        else{
            return new ResponseEntity<>(statusCode, HttpStatus.FORBIDDEN);
        }
    }

    /**
     * PULL-URI-Request API for DigiLocker
     * @param request
     * @param
     * @return
     */

    @RequestMapping(value = "/api/v1/pullDocUriRequest/{entityName}", method = RequestMethod.POST, produces =
            {MediaType.APPLICATION_XML_VALUE}, consumes = {MediaType.APPLICATION_XML_VALUE})
    public ResponseEntity<Object> pullDocURI(HttpServletRequest request) {

        String entityName = "StudentFromUP"; //- take entity name from input - TODO
        String statusCode = "1";
        Scanner scanner = null;
        String hmac = request.getHeader("x-digilocker-hmac");

        try {
            scanner = new Scanner(request.getInputStream(), "UTF-8");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        String xmlString = null;
        if(scanner!=null){
            Scanner scanner1 = scanner.useDelimiter("\\A");
            if(scanner1.hasNext())
                xmlString =  scanner1.next();
        }

        // GET Request xml and create object
        PullDocRequest pullDocRequest = null;
        try {
            pullDocRequest = DigiLockerUtils.processPullDocRequest(xmlString);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        boolean isValidReq = DigiLockerUtils.verifyHmac(pullDocRequest.getTs(), DIGILOCKER_KEY, hmac);
        if(!isValidReq){
            statusCode = "0";
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_XML);
            return new ResponseEntity<>(statusCode, HttpStatus.FORBIDDEN);
        }
        String credName = pullDocRequest.getDocDetails().getUri();
        byte[] cred = certificateService.getCred(credName);
        JsonNode result = null;
        // get stident by osid
        String osid = pullDocRequest.getTxn();
        try {
            result = registryHelper.getUserInfoFromRegistryByOsId(request, entityName, osid);
            Person person = DigiLockerUtils.getPersonDetail(result, entityName);
            PullDocResponse pullDocResponse = DigiLockerUtils.getDocPullUriResponse(osid,statusCode, cred,person);
            Object responseString = DigiLockerUtils.convertJaxbToPullDoc(pullDocResponse);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_XML);
            return new ResponseEntity<>(responseString, headers, HttpStatus.OK);
        } catch (Exception e) {
            statusCode = "0";
            e.printStackTrace();
            return new ResponseEntity<>(statusCode, HttpStatus.FORBIDDEN);
        }

    }

}
