package com.vic.castreceiver;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.AssetManager;
import android.net.http.SslError;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.util.Log;
import android.webkit.CookieManager;
import android.webkit.PermissionRequest;
import android.webkit.SslErrorHandler;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.CompoundButton;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;

import com.google.firebase.crashlytics.buildtools.reloc.org.apache.http.conn.util.InetAddressUtils;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class MainActivity extends AppCompatActivity {

	private static final String TAG = "VicCastReceiver";
	private static final String DESKTOP_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.121 Safari/537.36";
	private static final String SERVICE_TYPE_GOOGLE_CAST = "_googlecast._tcp";
	private static final String SERVICE_TYPE_HTTP_TCP = "_http._tcp";
	private static final String SERVICE_NAME = "VicCastReceiver";

	private WebView mWebView;
	private SwitchCompat mCastReceiverSwitch;
	private WifiManager mWifiManager;
	private WifiManager.MulticastLock mMulticastLock;

	private NsdManager mNsdManager;
	private NsdServiceInfo mNsdServiceInfo;

	private HttpURLConnection mUrlConnection;


	@SuppressLint({"MissingInflatedId", "SetJavaScriptEnabled"})
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		mWifiManager = (WifiManager)getSystemService(Context.WIFI_SERVICE);
		mNsdManager = (NsdManager)getSystemService(Context.NSD_SERVICE);

		mCastReceiverSwitch = findViewById(R.id.switch_cast_receiver);
		mCastReceiverSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
			@Override
			public void onCheckedChanged(CompoundButton compoundButton, boolean isChecked) {
				if (isChecked) {
					try {
						mMulticastLock = mWifiManager.createMulticastLock(SERVICE_NAME);
						mMulticastLock.setReferenceCounted(true);
						mMulticastLock.acquire();

						mNsdServiceInfo = new NsdServiceInfo();
						mNsdServiceInfo.setServiceType(SERVICE_TYPE_GOOGLE_CAST);
						mNsdServiceInfo.setPort(8009);
						InetAddress inetAddress = InetAddress.getByName(getIPAddress(true));
						Log.d(TAG, "onCreate inetAddress= " + inetAddress.toString());
						mNsdServiceInfo.setHost(inetAddress);
						mNsdServiceInfo.setServiceName(SERVICE_NAME);

						WifiInfo wifiInfo = mWifiManager.getConnectionInfo();
						String bssId = null;
						bssId = wifiInfo.getBSSID();
						Log.d(TAG, "onCreate: wifiInfo= " + wifiInfo);
						if (bssId == null || "02:00:00:00:00:00".equals(bssId)) {
							bssId = "FFFFFFFFFFFF";
						}
						bssId = bssId.toUpperCase(Locale.US);
						bssId = bssId.replace(":", "");

						String uuid = UUID.randomUUID().toString().replaceAll("-", "");
						mNsdServiceInfo.setAttribute("id", uuid);
						mNsdServiceInfo.setAttribute("bs", bssId);//BSSID
						mNsdServiceInfo.setAttribute("ca", "4101");
						mNsdServiceInfo.setAttribute("cd", uuid);
						mNsdServiceInfo.setAttribute("fn", SERVICE_NAME);
						mNsdServiceInfo.setAttribute("ic", "/setup/icon.png");
						mNsdServiceInfo.setAttribute("md", SERVICE_NAME);
						mNsdServiceInfo.setAttribute("nf", "1");
						mNsdServiceInfo.setAttribute("rm", "");
						mNsdServiceInfo.setAttribute("rmodel", SERVICE_NAME);
						mNsdServiceInfo.setAttribute("rs", "");
						mNsdServiceInfo.setAttribute("st", "0");
						mNsdServiceInfo.setAttribute("ve", "05");

						mNsdManager.registerService(mNsdServiceInfo, NsdManager.PROTOCOL_DNS_SD, mRegistrationListener);
						Log.d(TAG, "MultiCastLock acquire");
						//mWebView.loadUrl("javascript:window.location.reload(true)");
						mWebView.loadUrl("https://viccastreceiver.firebaseapp.com");
					} catch (Exception e) {
						e.printStackTrace();
					}

					new Thread(new Runnable() {
						@Override
						public void run() {
							Log.d(TAG, "run: run");
							getCertificate();
						}
					}).start();
				} else {
					if (mRegistrationListener != null) {
						mNsdManager.unregisterService(mRegistrationListener);
					}
					mMulticastLock.release();
					Log.d(TAG, "MultiCastLock release");
				}
			}
		});

		mWebView = findViewById(R.id.web_view);
		mWebView.getSettings().setUserAgentString(DESKTOP_USER_AGENT);
		mWebView.getSettings().setDomStorageEnabled(true);
		mWebView.getSettings().setJavaScriptEnabled(true);
		mWebView.getSettings().setLoadWithOverviewMode(true);
		mWebView.getSettings().setDisplayZoomControls(true);
		mWebView.getSettings().setJavaScriptCanOpenWindowsAutomatically(true);
		mWebView.getSettings().setUseWideViewPort(true);
		mWebView.getSettings().setAllowFileAccess(true);
		mWebView.getSettings().setCacheMode(WebSettings.LOAD_NO_CACHE);
		mWebView.getSettings().setLoadsImagesAutomatically(true);
		mWebView.getSettings().setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
		mWebView.getSettings().setAllowContentAccess(true);
		mWebView.getSettings().setSafeBrowsingEnabled(false);

		CookieManager.getInstance().setAcceptThirdPartyCookies(mWebView, true);
		mWebView.setWebViewClient(new WebViewClient() {
			@Override
			public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
				return false;
			}

			@Override
			public void onPageFinished(WebView view, String url) {
				super.onPageFinished(view, url);
			}

			@SuppressLint("WebViewClientOnReceivedSslError")
			@Override
			public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
				Log.d(TAG, "onReceivedSslError: error= " + error);
				handler.proceed();
			}

			@Nullable
			@Override
			public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
				return super.shouldInterceptRequest(view, request);
			}
		});
		mWebView.setWebChromeClient(new WebChromeClient() {
			@Override
			public void onPermissionRequest(PermissionRequest request) {
				String[] resources = request.getResources();
				for (int i = 0; i < resources.length; i++) {
					if (PermissionRequest.RESOURCE_PROTECTED_MEDIA_ID.equals(resources[i])) {
						request.grant(resources);
						return;
					}
				}
				super.onPermissionRequest(request);
			}
		});


	}

	public void getCertificate() {
		try {
//			Log.d(TAG, "getCertificate: start");
//			// Load CAs from an InputStream
//			// (could be from a resource or ByteArrayInputStream or ...)
//			CertificateFactory cf = CertificateFactory.getInstance("X.509");
//			// From https://www.washington.edu/itconnect/security/ca/load-der.crt
//			AssetManager am = getApplicationContext().getResources().getAssets();
//			InputStream caInput = am.open("cert.crt");
//			Certificate ca;
//			try {
//				ca = cf.generateCertificate(caInput);
//				Log.d(TAG, "ca=" + ((X509Certificate) ca).getSubjectDN());
//			} finally {
//				caInput.close();
//			}
//
//			// Create a KeyStore containing our trusted CAs
//			String keyStoreType = KeyStore.getDefaultType();
//			KeyStore keyStore = KeyStore.getInstance(keyStoreType);
//			keyStore.load(null, null);
//			keyStore.setCertificateEntry("ca", ca);
//
//			// Create a TrustManager that trusts the CAs in our KeyStore
//			String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
//			TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
//			tmf.init(keyStore);
//
//			// Create an SSLContext that uses our TrustManager
//			SSLContext context = SSLContext.getInstance("TLS");
//			context.init(null, tmf.getTrustManagers(), null);

			// Tell the URLConnection to use a SocketFactory from our SSLContext
			URL url = new URL("https://viccastreceiver.firebaseapp.com");
			mUrlConnection = (HttpURLConnection) url.openConnection();
			//urlConnection.setSSLSocketFactory(context.getSocketFactory());
			InputStream in = new BufferedInputStream(mUrlConnection.getInputStream());
			//readStream(in);

			Map<String, List<String>> header = mUrlConnection.getHeaderFields();
			Iterator<String> it = header.keySet().iterator();
			while (it.hasNext()) {
				String key = it.next();
				List<String> values = header.get(key);
				StringBuffer sb = new StringBuffer();
				for (int i = 0; i < values.size(); i++) {
					sb.append("," + values.get(i));
				}
				Log.d("kyu-URLConnection-Key", key + "=" + sb.toString().substring(1));
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			mUrlConnection.disconnect();
		}
	}


	public static String getIPAddress(boolean useIPv4) {
		try {
			List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
			for (NetworkInterface networkInterface : interfaces) {
				List<InetAddress> inetAddresses = Collections.list(networkInterface.getInetAddresses());
				for (InetAddress inetAddress : inetAddresses) {
					if (!inetAddress.isLoopbackAddress()) {
						String address = inetAddress.getHostAddress().toUpperCase();
						boolean isIPv4 = InetAddressUtils.isIPv4Address(address);
						if (useIPv4) {
							if (isIPv4)
								return address;
						} else {
							if (!isIPv4) {
								int delim = address.indexOf('%'); // drop ip6 port
								// suffix
								return delim < 0 ? address : address.substring(0, delim);
							}
						}
					}
				}
			}
		} catch (Exception ex) {
			// ignore
		}
		return "";
	}

	private final NsdManager.RegistrationListener mRegistrationListener = new NsdManager.RegistrationListener() {
		@Override
		public void onRegistrationFailed(NsdServiceInfo nsdServiceInfo, int errorCode) {
			Log.d(TAG, "onRegistrationFailed: info= " + nsdServiceInfo.toString() + " errorCode= " + errorCode);
		}

		@Override
		public void onUnregistrationFailed(NsdServiceInfo nsdServiceInfo, int errorCode) {
			Log.d(TAG, "onUnregistrationFailed: info= " + nsdServiceInfo.toString() + " errorCode= " + errorCode);
		}

		@Override
		public void onServiceRegistered(NsdServiceInfo nsdServiceInfo) {
			Log.d(TAG, "onServiceRegistered: info= " + nsdServiceInfo.toString());
		}

		@Override
		public void onServiceUnregistered(NsdServiceInfo nsdServiceInfo) {
			Log.d(TAG, "onServiceUnregistered: info= " + nsdServiceInfo.toString());
		}
	};

	@Override
	protected void onPause() {
		super.onPause();
	}

	@Override
	protected void onDestroy() {
		super.onDestroy();
		if (mMulticastLock != null) {
			mMulticastLock.release();
			Log.d(TAG, "onDestroy: MultiCastLock release");
		}
	}
}