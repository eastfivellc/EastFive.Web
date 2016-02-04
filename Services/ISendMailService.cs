using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BlackBarLabs.Web
{
    public interface ISendMailService
    {
        Task SendEmailMessageAsync(string toAddress, string fromAddress,
            string fromName, string subject, string html, IDictionary<string, List<string>> substitution = null);
    }
}