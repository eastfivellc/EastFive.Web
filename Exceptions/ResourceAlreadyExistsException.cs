using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BlackBarLabs.Web
{
    public class ResourceAlreadyExists : ResourceConflictException
    {
        private object currentOrderId;

        public ResourceAlreadyExists(object currentOrderId)
        {
            this.currentOrderId = currentOrderId;
        }
    }
}
