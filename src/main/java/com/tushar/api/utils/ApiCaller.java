package com.tushar.api.utils;

import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.*;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.*;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;


public class ApiCaller {

    private final static Logger LOG = Logger.getLogger(ApiCaller.class);

    /**
     * Method use to call delete api
     * @param httpContext
     * @param httpClient
     * @param url
     * @return CloseableHttpResponse
     * @throws IOException
     */
    public CloseableHttpResponse deleteApi(HttpClientContext httpContext, CloseableHttpClient httpClient, String url) throws IOException {
        HttpDelete deleteReq = new HttpDelete(url);
        CloseableHttpResponse response = httpClient.execute(deleteReq, httpContext);
        int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode != 200)
            LOG.warn("Delete API call failed with return code : " + statusCode);
        else
            LOG.info("Delete API call successfully executed");
        return response;
    }

    /**
     * Method use to call get api
     * @param httpContext
     * @param httpClient
     * @param url
     * @return apiOutput
     * @throws IOException
     */
    public String getApi(HttpClientContext httpContext, CloseableHttpClient httpClient, String url) throws IOException {
        HttpGet getReq = new HttpGet(url);
        CloseableHttpResponse response = httpClient.execute(getReq, httpContext);
        int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode != 200)
            LOG.warn("Get API call failed with return code : " + statusCode);
        else
            LOG.info("Get API call successfully executed");
        String apiOutput = EntityUtils.toString(response.getEntity());
        return apiOutput;
    }

    /**
     *
     * @param httpContext
     * @param httpClient
     * @param url
     * @param payloadStr
     * @return CloseableHttpResponse
     * @throws IOException
     */
    public CloseableHttpResponse putApi(HttpClientContext httpContext, CloseableHttpClient httpClient, String url
            , String payloadStr) throws IOException {
        HttpPut putReq = new HttpPut(url);
        StringEntity payload = new StringEntity(payloadStr);
        payload.setContentType("application/json");
        putReq.setEntity(payload);
        CloseableHttpResponse response = httpClient.execute(putReq, httpContext);
        int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode != 200)
            LOG.warn("Get API call failed with return code : " + statusCode);
        else
            LOG.info("Get API call successfully executed");
        return response;
    }

    /**
     *
     * @param httpContext
     * @param httpClient
     * @param url
     * @param payloadStr
     * @return CloseableHttpResponse
     * @throws IOException
     */
    public CloseableHttpResponse postApi(HttpClientContext httpContext, CloseableHttpClient httpClient, String url
            , String payloadStr) throws IOException {
        HttpPost postReq = new HttpPost(url);
        StringEntity payload = new StringEntity(payloadStr);
        payload.setContentType("application/json");
        postReq.setEntity(payload);
        CloseableHttpResponse response = httpClient.execute(postReq, httpContext);
        int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode != 200)
            LOG.warn("Post API call failed with return code : " + statusCode);
        else
            LOG.info("Post API call successfully executed");
        return response;
    }

    /**
     * This method will generate HttpClientContext for basic authentication
     * @param hostName
     * @param port
     * @param scheme (http/https)
     * @param username
     * @param password
     * @return HttpClientContext
     */
    public HttpClientContext getHttpContext(String hostName, int port, String scheme, String username, String password) {
        HttpClientContext httpClientContext = HttpClientContext.create();
        HttpHost httpHost = new HttpHost(hostName, port, scheme);
        BasicCredentialsProvider basicCredentialsProvider = new BasicCredentialsProvider();
        basicCredentialsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(username, password));
        BasicAuthCache basicAuthCache = new BasicAuthCache();
        basicAuthCache.put(httpHost, new BasicScheme());
        httpClientContext.setCredentialsProvider(basicCredentialsProvider);
        httpClientContext.setAuthCache(basicAuthCache);
        return  httpClientContext;
    }

    /**
     * This method will generate CloseableHttpClient by skipping certificates
     * @param httpClientContext
     * @return CloseableHttpClient
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws KeyManagementException
     */
    public CloseableHttpClient getHttpClient(HttpClientContext httpClientContext)
            throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        CloseableHttpClient closeableHttpClient = HttpClientBuilder.create().build();
        SSLContext sslContext = new SSLContextBuilder()
                .loadTrustMaterial(null, (certificates, authType) -> true).build();
        closeableHttpClient = HttpClients.custom().setSSLContext(sslContext)
                .setSSLHostnameVerifier(new NoopHostnameVerifier()).build();
        return closeableHttpClient;
    }
}
