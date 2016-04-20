using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace BlackBarLabs.Web
{
    public delegate void EmailSendSuccessDelegate(string toAddress);

    public interface ISendMailService
    {
        Task SendEmailMessageAsync(string toAddress, string fromAddress,
            string fromName, string subject, string html, EmailSendSuccessDelegate onSuccess,
            IDictionary<string, List<string>> substitution,
            Action<string, IDictionary<string, string>> logIssue);
    }
}