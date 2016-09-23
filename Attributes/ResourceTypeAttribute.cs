using System;

namespace BlackBarLabs.Web
{
    [AttributeUsage(AttributeTargets.Class)]
    public class ResourceTypeAttribute : System.Attribute
    {
        public ResourceTypeAttribute()
        {
        }
        
        private string urn;
        public string Urn
        {
            get
            {
                return this.urn;
            }
            set
            {
                urn = value;
            }
        }
        
    }
}
