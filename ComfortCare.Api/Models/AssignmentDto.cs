using Newtonsoft.Json;

namespace ComfortCare.Api.Models
{
    /// <summary>
    /// This dto class is only used in the gateway for mapping data of the assignment to the ui layer
    /// </summary>
    public class AssignmentDto
    {
        #region Properties
        [JsonProperty("titel")] 
        public string Titel { get; set; }

        [JsonProperty("description")]
        public string Description { get; set; }

        [JsonProperty("citizenName")]
        public string CitizenName { get; set; }

        [JsonProperty("startDate")]
        public DateTime StartDate { get; set; }

        [JsonProperty("endDate")]
        public DateTime EndDate { get; set; }

        [JsonProperty("address")]
        public string Address { get; set; }
        #endregion
    }
}
