using Amazon.Lambda.Core;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace AWSInspector
{

    class CfnResponse
    {
        public enum OpsStatus
        {
            Success = 1,
            Fail = 2
        }

        public const string RequestType_Create = "Create";
        public const string RequestType_Update = "Update";
        public const string RequestType_Delete = "Delete";

        public string Send(JObject input, ILambdaContext context, OpsStatus Status, Object data)
        {
            CloudFormationResponse cf = new CloudFormationResponse();
            cf.Status = Status == OpsStatus.Success ? "SUCCESS" : "FAILED"; //Values should be either SUCCESS or FAILED
            cf.PhysicalResourceId = context.LogStreamName;
            cf.StackId = input["StackId"].ToString();
            cf.RequestId = input["RequestId"].ToString();
            cf.LogicalResourceId = input["LogicalResourceId"].ToString();
            cf.Reason = "OK";
            cf.Data = data;

            Console.WriteLine(JObject.FromObject(cf).ToString(Newtonsoft.Json.Formatting.None));

            var t = PostToS3Async(input["ResponseURL"].ToString(), cf);
            t.Wait();
            return t.Result.ToString();
        }
        public string Send(JObject input, ILambdaContext context, OpsStatus Status, string Reason, Object data)
        {
            CloudFormationResponse cf = new CloudFormationResponse();
            cf.Status = Status == OpsStatus.Success ? "SUCCESS" : "FAILED"; //Values should be either SUCCESS or FAILED
            cf.PhysicalResourceId = context.LogStreamName;
            cf.StackId = input["StackId"].ToString();
            cf.RequestId = input["RequestId"].ToString();
            cf.LogicalResourceId = input["LogicalResourceId"].ToString();
            cf.Reason = Reason;
            cf.Data = data;

            Console.WriteLine(JObject.FromObject(cf).ToString(Newtonsoft.Json.Formatting.None));

            var t = PostToS3Async(input["ResponseURL"].ToString(), cf);
            t.Wait();
            return t.Result.ToString();
        }
        private async Task<bool> PostToS3Async(String presignedUrl, Object data)
        {
            String jsonData = JObject.FromObject(data).ToString(Newtonsoft.Json.Formatting.None);
            StringContent val = new StringContent(jsonData);
            val.Headers.Clear();
            val.Headers.TryAddWithoutValidation("content-type", "");
            val.Headers.TryAddWithoutValidation("content-length", jsonData.Length.ToString());

            var client = new HttpClient();
            client.DefaultRequestHeaders.Clear();

            await client.PutAsync(presignedUrl, val);
            return true;

        }

        private class CloudFormationResponse
        {
            public string Status { get; set; }
            public string PhysicalResourceId { get; set; }
            public string StackId { get; set; }
            public string RequestId { get; set; }
            public string LogicalResourceId { get; set; }
            public string Reason { get; set; }
            public Object Data { get; set; }
        }
    }
}
