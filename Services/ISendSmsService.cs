using System.Threading.Tasks;

namespace BlackBarLabs.Web
{
    public interface ISendSmsService
    {
        bool SendSmsMessage(string fromNumber, string toNumber, string text);
    }
}