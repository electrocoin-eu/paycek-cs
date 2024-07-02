using System.Collections.Specialized;
using System.Text;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Digests;


namespace PaycekNS
{
    public class Paycek
    {
        private string apiKey;
        private string apiSecret;
        private string apiHost;
        private string apiPrefix;
        private Encoding encoding;

        public Paycek(string apiKey, string apiSecret)
        {
            this.apiKey = apiKey;
            this.apiSecret = apiSecret;
            this.apiHost = "https://paycek.io";
            this.apiPrefix = "/processing/api";
            this.encoding = Encoding.UTF8;
        }

        private void UpdateDigest(Sha3Digest digest, string value)
        {
            digest.Update(0);
            digest.BlockUpdate(encoding.GetBytes(value), 0, value.Length);
        }

        private string GenerateMacHash(string nonceStr, string endpoint, string bodyString, string httpMethod="POST", string contentType="application/json")
        {
            Sha3Digest digest = new Sha3Digest(512);
            byte[] output = new byte[digest.GetDigestSize()];

            UpdateDigest(digest, apiKey);
            UpdateDigest(digest, apiSecret);
            UpdateDigest(digest, nonceStr);
            UpdateDigest(digest, httpMethod);
            UpdateDigest(digest, endpoint);
            UpdateDigest(digest, contentType);
            UpdateDigest(digest, bodyString);
            digest.Update(0);

            digest.DoFinal(output, 0);

            return BitConverter.ToString(output).ToLower().Replace("-", "");
        }

        private dynamic ApiCall(string endpoint, Dictionary<string, object> body)
        {
            string prefixedEndpoint = $"{apiPrefix}/{endpoint}";
            string bodyString = JsonConvert.SerializeObject(body);
            string nonceStr = ((Int64)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalMilliseconds).ToString();

            string macHash = GenerateMacHash(nonceStr, prefixedEndpoint, bodyString);

            HttpClient client = new HttpClient();
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, apiHost + prefixedEndpoint)
            {
                Content = new StringContent(bodyString, encoding, "application/json")
            };
            request.Headers.Add("ApiKeyAuth-Key", apiKey);
            request.Headers.Add("ApiKeyAuth-Nonce", nonceStr);
            request.Headers.Add("ApiKeyAuth-MAC", macHash);

            HttpResponseMessage response = client.Send(request);

            using StreamReader reader = new StreamReader(response.Content.ReadAsStream());
                    
            dynamic? responseDictionary = JsonConvert.DeserializeObject<dynamic>(reader.ReadToEnd());
            if (responseDictionary is null)
            {
                throw new Exception($"There was an error deserializing response received from endpoint {endpoint}.\nResponse: {response}");
            }

            return responseDictionary;
        }

        private bool TimingSafeEqual(string generatedMac, string receivedMac) 
        {
            bool equal = generatedMac.Length == receivedMac.Length;

            for(int i = 0; i < generatedMac.Length; ++i)
            {
                equal &= receivedMac.Length >= i + 1 && generatedMac[i] == receivedMac[i];
            }

            return equal;
        }

        /// <summary>
        /// This method is used to verify callback was encoded by paycek.
        /// A mac digest will be created by encoding nonce from headers, endpoint, body bytes, your api key and secret, http method and content type.
        /// That value will be compared with mac digest from headers.
        /// </summary>
        /// <param name="headers">callback headers</param>
        /// <param name="endpoint">callback endpoint</param>
        /// <param name="bodyString">callback body string</param>
        /// <param name="httpMethod">callback http method</param>
        /// <param name="contentType">callback content type</param>
        /// <returns>True if the generated mac digest is equal to the one received in headers, False otherwise</returns>
        public bool CheckHeaders(NameValueCollection headers, string endpoint, string bodyString, string httpMethod = "GET", string contentType = "")
        {
            try
            {
                Dictionary<string, string> headersLower = headers.AllKeys.ToDictionary(key => (key ?? "").ToLower(), key => headers[key] ?? "");
                string generatedMac = GenerateMacHash(headersLower["apikeyauth-nonce"], endpoint, bodyString, httpMethod, contentType);

                return TimingSafeEqual(generatedMac, headersLower["apikeyauth-mac"]);
            }
            catch
            {
                return false;
            }
        }

        private void InsertOptionalFields(Dictionary<string, object> body, Dictionary<string, object>? optionalFields)
        {
            if (optionalFields is not null)
            {
                foreach(KeyValuePair<string, object> entry in optionalFields)
                {
                    body.Add(entry.Key, entry.Value);
                }
            }
        }

        /// <param name="optionalFields">
        /// Optional fields:
        /// <para>payment_id: string</para>
        /// <para>location_id: string</para>
        /// <para>items: array</para>
        /// <para>email: string</para>
        /// <para>success_url: string</para>
        /// <para>fail_url: string</para>
        /// <para>back_url: string</para>
        /// <para>success_url_callback: string</para>
        /// <para>fail_url_callback: string</para>
        /// <para>status_url_callback: string</para>
        /// <para>description: string</para>
        /// <para>language: string</para>
        /// <para>generate_pdf: bool</para>
        /// <para>client_fields: object</para>
        /// </param>
        public string GeneratePaymentUrl(string profileCode, string dstAmount, Dictionary<string, object>? optionalFields = null)
        {
            dynamic payment = OpenPayment(profileCode, dstAmount, optionalFields);

            try 
            {
                return payment.data.payment_url;
            } catch (Exception ex)
            {
                Console.WriteLine(payment);
                throw ex;
            }
        }

        public dynamic GetPayment(string paymentCode)
        {
            Dictionary<string, object>  body = new Dictionary<string, object>();
            body.Add("payment_code", paymentCode);

            return ApiCall("payment/get", body);
        }

        /// <param name="profileCode">The profile code for the payment.</param>
        /// <param name="dstAmount">The amount of the payment.</param>
        /// <param name="optionalFields">
        /// Optional fields:
        /// <para>location_id: string</para>
        /// <para>items: array</para>
        /// <para>email: string</para>
        /// <para>success_url: string</para>
        /// <para>fail_url: string</para>
        /// <para>back_url: string</para>
        /// <para>success_url_callback: string</para>
        /// <para>fail_url_callback: string</para>
        /// <para>status_url_callback: string</para>
        /// <para>description: string</para>
        /// <para>language: string</para>
        /// <para>generate_pdf: bool</para>
        /// <para>client_fields: object</para>
        /// </param>
        /// <remarks>
        /// You can implement getting payment status in 3 ways:
        /// <list type="number">
        /// <item><b>Provide</b> <c>status_url_callback</c> upon opening a payment and receive status updates on your endpoint.</item>
        /// <item><b>Provide</b> <c>success_url_callback</c> <b>and</b> <c>fail_url_callback</c> upon opening a payment and receive success and fail updates on your endpoints.</item>
        /// <item><b>Manually poll</b> <c>payment/get</c> to check payment status.</item>
        /// </list>
        /// <b>Do not use</b> <c>fail_url</c> <b>and</b> <c>success_url</c> <b>to update payment status in your system. These URLs are used ONLY for redirecting users back to your shop.</b>
        /// <para><b>Authorization</b></para>
        /// If you decide to use callbacks, you <b>must check the headers for every callback</b> to ensure they are authorized.
        /// If a callback doesn't have a valid Authorization header, your server must respond with a <b>401 Unauthorized</b> status. If the callback has a valid Authorization header, your server must respond with a <b>200 OK</b> status.
        /// <para><b>Integration Testing</b></para>
        /// In order to ensure system security, on every new payment, an automated integration test will check if your integration is secure.
        /// An API call with an invalid Authorization header will be made to each of your callback endpoints. If any endpoint returns a status other than 401 for requests with an invalid Authorization header, <b>all ongoing payments will be canceled</b>, and your <b>profile will be blocked</b> to prevent unauthorized transactions. Ensure your endpoints are correctly configured to handle authorization and respond appropriately.
        /// <para><i>Test profiles won't be blocked even if the response for callbacks with an invalid Authorization header returns an invalid status. The payment will still be canceled.</i></para>
        /// </remarks>
        public dynamic OpenPayment(string profileCode, string dstAmount, Dictionary<string, object>? optionalFields = null)
        {
            Dictionary<string, object>  body = new Dictionary<string, object>();
            body.Add("profile_code", profileCode);
            body.Add("dst_amount", dstAmount);
            
            InsertOptionalFields(body, optionalFields);

            return ApiCall("payment/open", body);
        }

        /// <param name="optionalFields">
        /// Optional fields:
        /// <para>src_protocol: string</para>
        /// </param>
        public dynamic UpdatePayment(string paymentCode, string srcCurrency, Dictionary<string, object>? optionalFields = null)
        {
            Dictionary<string, object>  body = new Dictionary<string, object>();
            body.Add("payment_code", paymentCode);
            body.Add("src_currency", srcCurrency);

            InsertOptionalFields(body, optionalFields);

            return ApiCall("payment/update", body);
        }

        public dynamic CancelPayment(string paymentCode)
        {
            Dictionary<string, object>  body = new Dictionary<string, object>();
            body.Add("payment_code", paymentCode);

            return ApiCall("payment/cancel", body);
        }

        public dynamic GetProfileInfo(string profileCode)
        {
            Dictionary<string, object>  body = new Dictionary<string, object>();
            body.Add("profile_code", profileCode);

            return ApiCall("profile_info/get", body);
        }

        /// <param name="details">
        /// Withdraw details object with fields:
        /// <para> iban: string (required)</para>
        /// <para> purpose: string</para>
        /// <para> model: string</para>
        /// <para> pnb: string</para>
        /// </param>
        /// <param name="optionalFields">
        /// Optional fields:
        /// <para> id: string</para>
        /// </param>
        public dynamic ProfileWithdraw(string profileCode, string method, string amount, Dictionary<string, object> details, Dictionary<string, object>? optionalFields = null)
        {
            Dictionary<string, object>  body = new Dictionary<string, object>();
            body.Add("profile_code", profileCode);
            body.Add("method", method);
            body.Add("amount", amount);
            body.Add("details", details);

            InsertOptionalFields(body, optionalFields);

            return ApiCall("profile/withdraw", body);
        }

        /// <param name="profileAutomaticWithdrawDetails">
        /// Automatic withdraw details object with fields:
        /// <para>iban: string (required)</para>
        /// <para>purpose: string</para>
        /// <para>model: string</para>
        /// <para>pnb: string</para>      
        /// </param>
        /// <param name="optionalFields">
        /// Optional fields:
        /// <para>type: string</para>
        /// <para>oib: string</para>
        /// <para>vat: string</para>
        /// <para>profile_name: string</para>
        /// <para>profile_email: string</para>
        /// <para>profile_type: string</para>
        /// </param>
        public dynamic CreateAccount(string email, string name, string street, string city, string country, string profileCurrency, string profileAutomaticWithdrawMethod, Dictionary<string, object> profileAutomaticWithdrawDetails, Dictionary<string, object>? optionalFields = null)
        {
            Dictionary<string, object>  body = new Dictionary<string, object>();
            body.Add("email", email);
            body.Add("name", name);
            body.Add("street", street);
            body.Add("city", city);
            body.Add("country", country);
            body.Add("profile_currency", profileCurrency);
            body.Add("profile_automatic_withdraw_method", profileAutomaticWithdrawMethod);
            body.Add("profile_automatic_withdraw_details", profileAutomaticWithdrawDetails);

            InsertOptionalFields(body, optionalFields);

            return ApiCall("account/create", body);
        }

        /// <param name="profileAutomaticWithdrawDetails">
        /// Automatic withdraw details object with fields:
        /// <para>iban: string (required)</para>
        /// <para>purpose: string</para>
        /// <para>model: string</para>
        /// <para>pnb: string</para>      
        /// </param>
        /// <param name="optionalFields">
        /// Optional fields:
        /// <para>type: string</para>
        /// <para>oib: string</para>
        /// <para>vat: string</para>
        /// <para>profile_name: string</para>
        /// <para>profile_email: string</para>
        /// </param>
        public dynamic CreateAccountWithPassword(string email, string password, string name, string street, string city, string country, string profileCurrency, string profileAutomaticWithdrawMethod, Dictionary<string, object> profileAutomaticWithdrawDetails, Dictionary<string, object>? optionalFields = null)
        {
            Dictionary<string, object>  body = new Dictionary<string, object>();
            body.Add("email", email);
            body.Add("password", password);
            body.Add("name", name);
            body.Add("street", street);
            body.Add("city", city);
            body.Add("country", country);
            body.Add("profile_currency", profileCurrency);
            body.Add("profile_automatic_withdraw_method", profileAutomaticWithdrawMethod);
            body.Add("profile_automatic_withdraw_details", profileAutomaticWithdrawDetails);

            InsertOptionalFields(body, optionalFields);

            return ApiCall("account/create_with_password", body);
        }

        /// <param name="optionalFields">
        /// Optional fields:
        /// <para>location_id: string</para>
        /// </param>
        public dynamic GetReports(string profileCode, string datetimeFrom, string datetimeTo, Dictionary<string, object>? optionalFields = null)
        {
            Dictionary<string, object>  body = new Dictionary<string, object>();
            body.Add("profile_code", profileCode);
            body.Add("datetime_from", datetimeFrom);
            body.Add("datetime_to", datetimeTo);

            InsertOptionalFields(body, optionalFields);

            return ApiCall("reports/get", body);
        }
    }
}
