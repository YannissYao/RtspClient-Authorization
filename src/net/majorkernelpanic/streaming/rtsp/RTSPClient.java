package net.majorkernelpanic.streaming.rtsp;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class RTSPClient {


    private Socket mSocket;
    private String mHost;
    private String mUsername;
    private String mPassword;
    private String mPath;
    private String mAuthorization;
    private BufferedReader mBufferedReader;
    private OutputStream mOutputStream;
    private int mCSeq, mPort;


    public void parseUrl(String url)throws Exception {
            if (!url.substring(0, 7).equals("rtsp://")) throw new RuntimeException("URL格式错误");
            url = url.substring(7, url.length());
            if (url.contains("@")) {
                String str[] = url.split("@");
                this.mUsername = str[0].split(":")[0];
                this.mPassword = str[0].split(":")[1];
                this.mPath = str[1].substring(str[1].indexOf("/"), str[1].length());
                String host_port = str[1].substring(0, str[1].indexOf("/"));
                this.mHost = host_port.split(":")[0];
                this.mPort = Integer.parseInt(host_port.split(":")[1]);
            } else {
                String str[] = url.split(":");
                this.mHost = str[0];
                this.mPort = Integer.parseInt(str[1].substring(0, str[1].indexOf("/")));
                this.mPath = str[1].substring(str[1].indexOf("/"), str[1].length());
            }
    }

    private String badUrlCheck(String url) {
        Response response = null;
        String code = "";

        try {
            parseUrl(url);
        } catch (Exception e) {
            code = "URL格式错误";
            return code;
        }
        try {
            mSocket = new Socket();
            mSocket.connect(new InetSocketAddress(mHost, mPort), 3000);
            mBufferedReader = new BufferedReader(new InputStreamReader(mSocket.getInputStream()));
            mOutputStream = mSocket.getOutputStream();
            String request = "DESCRIBE rtsp://" + mHost + ":" + mPort + mPath + " RTSP/1.0\r\n" +
                    "CSeq: " + (++mCSeq) + "\r\n" +
                    "Content-Type: application/sdp \r\n\r\n";
            mOutputStream.write(request.getBytes("UTF-8"));
            response = Response.parseResponse(mBufferedReader);
            if (response.status == 401) {
                whiles(response);
                response = Response.parseResponse(mBufferedReader);
                if (response.status == 401) {
                    code = "用户名密码错误";
                } else {
                    code = String.valueOf(response.status);
                }
            } else {
                code = String.valueOf(response.status);
            }
        } catch (IOException e) {
            e.printStackTrace();
            code = "无效的IP或者端口";
        }
        return code;
    }

    public void whiles(Response response) throws IOException {
        String nonce, realm;
        Matcher m;

        if (mUsername == null || mPassword == null)
            throw new IllegalStateException("Authentication is enabled and setCredentials(String,String) was not called !");

        try {
            m = Response.rexegAuthenticate.matcher(response.headers.get("www-authenticate"));
            m.find();
            nonce = m.group(2);
            realm = m.group(1);
        } catch (Exception e) {
            throw new IOException("Invalid response from server");
        }

        String uri = "rtsp://" + mHost + ":" + mPort + mPath;
        String hash1 = computeMd5Hash(mUsername + ":" + m.group(1) + ":" + mPassword);
        String hash2 = computeMd5Hash("DESCRIBE" + ":" + uri);
        String hash3 = computeMd5Hash(hash1 + ":" + m.group(2) + ":" + hash2);

        mAuthorization = "Digest username=\"" + mUsername + "\",realm=\"" + realm + "\",nonce=\"" + nonce + "\",uri=\"" + uri + "\",response=\"" + hash3 + "\"\r\n";

        String request = "DESCRIBE rtsp://" + mHost + ":" + mPort + mPath + " RTSP/1.0\r\n" +
                "CSeq: " + (++mCSeq) + "\r\n" +
                "Authorization: " + mAuthorization +
                "Content-Type: application/sdp \r\n\r\n";


        mOutputStream.write(request.getBytes("UTF-8"));
    }


    final protected static char[] hexArray = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private String computeMd5Hash(String buffer) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("MD5");
            return bytesToHex(md.digest(buffer.getBytes("UTF-8")));
        } catch (NoSuchAlgorithmException ignore) {
        } catch (UnsupportedEncodingException e) {
        }
        return "";
    }

    static class Response {

        // Parses method & uri
        public static final Pattern regexStatus = Pattern.compile("RTSP/\\d.\\d (\\d+) (\\w+)", Pattern.CASE_INSENSITIVE);
        // Parses a request header
        public static final Pattern rexegHeader = Pattern.compile("(\\S+):(.+)", Pattern.CASE_INSENSITIVE);
        // Parses a WWW-Authenticate header
        public static final Pattern rexegAuthenticate = Pattern.compile("realm=\"(.+)\",\\s+nonce=\"(\\w+)\"", Pattern.CASE_INSENSITIVE);
        // Parses a Session header
        public static final Pattern rexegSession = Pattern.compile("(\\d+)", Pattern.CASE_INSENSITIVE);
        // Parses a Transport header
        public static final Pattern rexegTransport = Pattern.compile("client_port=(\\d+)-(\\d+).+server_port=(\\d+)-(\\d+)", Pattern.CASE_INSENSITIVE);


        public int status;
        public HashMap<String, String> headers = new HashMap<String, String>();

        /**
         * Parse the method, uri & headers of a RTSP request
         */
        public static Response parseResponse(BufferedReader input) throws IOException, IllegalStateException, SocketException {
            Response response = new Response();
            String line;
            Matcher matcher;
            // Parsing request method & uri
            if ((line = input.readLine()) == null) throw new SocketException("Connection lost");
            matcher = regexStatus.matcher(line);
            matcher.find();
            response.status = Integer.parseInt(matcher.group(1));

            // Parsing headers of the request
            while ((line = input.readLine()) != null) {
                //Log.e(TAG,"l: "+line.length()+"c: "+line);
                if (line.length() > 3) {
                    matcher = rexegHeader.matcher(line);
                    matcher.find();
                    if (response.headers.get("www-authenticate") == null)
                        response.headers.put(matcher.group(1).toLowerCase(Locale.US), matcher.group(2));
                } else {
                    break;
                }
            }
            if (line == null) throw new SocketException("Connection lost");
            return response;
        }
    }

    public static void main(String[] args) {
        RTSPClient client = new RTSPClient();

//        client.mHost = "1664195xg2.iask.in";
//        client.mPort = 1554;
//        client.mPath = "/Streaming/Channels/901";
//
        String response = client.badUrlCheck("rtsp://username:password@ip:port/cam/realmonitor?channel=4&subtype=1");
        if (response.equals("") || response.equals("200")) {
            System.out.println("OK");
        } else {
            System.out.println(response);
        }
    }
}
